using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace AccessControl.Infrastructure.Storage;

/// <summary>
/// The files of one audit log: the active <c>&lt;name&gt;.jsonl</c> plus archived <c>&lt;name&gt;.&lt;last seq&gt;.jsonl</c>
/// segments. Handles rotation, retention, torn-line repair and reading lines across segments.
/// Not thread-safe: <see cref="ChainedJsonLinesLog"/> serialises every call that touches the files.
/// </summary>
internal sealed partial class AuditLogSegments
{
    private const string Extension = ".jsonl";
    private static readonly byte[] NewLine = "\n"u8.ToArray();

    private readonly string _name;
    private readonly string _directory;
    private readonly Regex _archivedName;
    private readonly long _segmentMaxBytes;
    private readonly int? _retentionDays;
    private readonly TimeProvider _clock;
    private readonly ILogger _logger;

    public AuditLogSegments(string name, StorageOptions options, TimeProvider clock, ILogger logger)
    {
        _name = name;
        _directory = Path.GetFullPath(options.DataDirectory);
        Directory.CreateDirectory(_directory);
        ActivePath = Path.Combine(_directory, name + Extension);
        _archivedName = new Regex($"^{Regex.Escape(name)}\\.[0-9]+{Regex.Escape(Extension)}$", RegexOptions.CultureInvariant);
        _segmentMaxBytes = options.AuditSegmentMaxBytes > 0 ? options.AuditSegmentMaxBytes : long.MaxValue;
        _retentionDays = options.AuditRetentionDays;
        _clock = clock;
        _logger = logger;
    }

    public string ActivePath { get; }

    /// <summary>Archives the active file once it reaches the size limit, then applies retention.</summary>
    /// <param name="lastSequence">The newest sequence in the active file; it names the archived segment.</param>
    public void RotateIfFull(long lastSequence)
    {
        var info = new FileInfo(ActivePath);
        if (!info.Exists || info.Length < _segmentMaxBytes)
        {
            return;
        }

        var archived = Path.Combine(
            _directory, $"{_name}.{lastSequence.ToString("D12", CultureInfo.InvariantCulture)}{Extension}");
        File.Move(ActivePath, archived);
        Log.Rotated(_logger, _name, Path.GetFileName(archived));
        ApplyRetention();
    }

    public void ApplyRetention()
    {
        if (_retentionDays is not { } days)
        {
            return;
        }

        var cutoff = _clock.GetUtcNow().UtcDateTime.AddDays(-days);
        foreach (var path in Archived())
        {
            if (File.GetLastWriteTimeUtc(path) < cutoff)
            {
                File.Delete(path);
                Log.SegmentExpired(_logger, _name, Path.GetFileName(path), days);
            }
        }
    }

    /// <summary>If the process died mid-append, end the torn line so the next append starts cleanly.</summary>
    public void TerminateTornLine()
    {
        if (!File.Exists(ActivePath))
        {
            return;
        }

        using var stream = new FileStream(ActivePath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read | FileShare.Delete);
        if (stream.Length == 0)
        {
            return;
        }

        stream.Seek(-1, SeekOrigin.End);
        if (stream.ReadByte() != '\n')
        {
            stream.Write(NewLine);
            stream.Flush(flushToDisk: true);
            Log.TornLineRepaired(_logger, ActivePath);
        }
    }

    /// <summary>The newest complete chained entry: in the active file, else in the newest archived segment.</summary>
    public (long Sequence, string Hash) FindChainHead()
    {
        var newestFirst = Archived();
        newestFirst.Reverse();
        foreach (var path in newestFirst.Prepend(ActivePath))
        {
            if (!File.Exists(path))
            {
                continue;
            }

            (long, string)? head = null;
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var reader = new StreamReader(stream, Encoding.UTF8))
            {
                while (reader.ReadLine() is { } text)
                {
                    if (!text.StartsWith("{\"seq\":", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    var line = AuditLogLine.Parse(path, 0, text, includeRaw: false);
                    if (line.Kind == AuditLineKind.Chained)
                    {
                        head = (line.Sequence, line.Hash!);
                    }
                }
            }

            if (head is { } found)
            {
                return found;
            }
        }

        return (0, AuditChainHasher.EmptyHash);
    }

    /// <summary>
    /// Opens every segment, oldest first. Open handles survive a later rotation or retention, so a reader
    /// neither misses nor repeats a segment. The caller owns the streams; <see cref="ReadLinesAsync"/> disposes them.
    /// </summary>
    public List<(string Path, FileStream Stream)> OpenAll()
    {
        var segments = new List<(string, FileStream)>();
        try
        {
            foreach (var path in Archived().Append(ActivePath))
            {
                try
                {
                    segments.Add((path, new FileStream(
                        path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                        bufferSize: 64 * 1024, useAsync: true)));
                }
                catch (FileNotFoundException)
                {
                    // No active file yet, or a segment removed by retention since it was listed.
                }
            }

            return segments;
        }
        catch
        {
            foreach (var (_, stream) in segments)
            {
                stream.Dispose();
            }

            throw;
        }
    }

    /// <summary>Every non-empty line of the opened segments, in order. Disposes the streams when done.</summary>
    public async IAsyncEnumerable<AuditLogLine> ReadLinesAsync(
        List<(string Path, FileStream Stream)> segments,
        bool includeRaw,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        try
        {
            foreach (var (path, stream) in segments)
            {
                using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
                var lineNumber = 0;
                while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } text)
                {
                    lineNumber++;
                    if (text.Length == 0)
                    {
                        continue;
                    }

                    var line = AuditLogLine.Parse(path, lineNumber, text, includeRaw);
                    if (line.Kind == AuditLineKind.Corrupt)
                    {
                        Log.CorruptLine(_logger, lineNumber, path);
                    }

                    yield return line;
                }
            }
        }
        finally
        {
            foreach (var (_, stream) in segments)
            {
                await stream.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>Archived segments oldest first. Their names embed a zero-padded sequence number.</summary>
    private List<string> Archived() =>
        Directory.EnumerateFiles(_directory, _name + ".*" + Extension)
            .Where(p => _archivedName.IsMatch(Path.GetFileName(p)))
            .Order(StringComparer.Ordinal)
            .ToList();

    private static partial class Log
    {
        [LoggerMessage(EventId = 3100, Level = LogLevel.Warning, Message = "Skipping unreadable audit line {LineNumber} in {Path}")]
        public static partial void CorruptLine(ILogger logger, int lineNumber, string path);

        [LoggerMessage(EventId = 3101, Level = LogLevel.Warning, Message = "Audit log {Path} ended mid-line (previous crash or failed write); terminated the partial line")]
        public static partial void TornLineRepaired(ILogger logger, string path);

        [LoggerMessage(EventId = 3102, Level = LogLevel.Information, Message = "Audit log {Log} rotated to {Segment}")]
        public static partial void Rotated(ILogger logger, string log, string segment);

        [LoggerMessage(EventId = 3103, Level = LogLevel.Warning, Message = "Audit log {Log}: deleted segment {Segment} (older than the {Days}-day retention period)")]
        public static partial void SegmentExpired(ILogger logger, string log, string segment, int days);
    }
}
