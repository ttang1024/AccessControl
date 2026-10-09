using System.Buffers;
using System.Collections.Concurrent;
using System.Text.Json;
using AccessControl.Application.Abstractions;
using Microsoft.Extensions.Logging;

namespace AccessControl.Infrastructure.Storage;

/// <summary>
/// Append-only JSON Lines log with a tamper-evident hash chain and size-based rotation.
/// <para>
/// Each line is <c>{"seq":n,"prev":h(n-1),"hash":h(n),"data":{...}}</c>; see <see cref="AuditChainHasher"/>.
/// Editing, deleting, inserting or reordering a line breaks the chain from that point.
/// </para>
/// <para>
/// Files are managed by <see cref="AuditLogSegments"/>: when the active file reaches the size limit it is archived
/// and the chain continues in a new file. The chain starts at entry 1, or continues from the signed anchor left by
/// retention (<see cref="AuditChainAnchor"/>); a chain that starts anywhere else had its oldest entries removed.
/// </para>
/// <para>
/// Appends are serialized and fully written (optionally fsync'd) before returning. A torn final line from a
/// crash is terminated on startup and skipped on read; the chain continues from the last complete entry.
/// </para>
/// </summary>
internal sealed partial class ChainedJsonLinesLog : IDisposable
{
    private static readonly byte[] NewLine = "\n"u8.ToArray();

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly ConcurrentQueue<(IReadOnlyList<byte[]> Payloads, TaskCompletionSource Appended)> _queued = new();
    private readonly AuditLogSegments _segments;
    private readonly AuditChainHasher _hasher;
    private readonly bool _flushToDisk;

    // Time range of each archived segment, by path; the stamp (length, last write) detects a replaced file.
    private readonly ConcurrentDictionary<string, ((long Length, DateTime LastWrite) Stamp, SegmentTimeRange Range)> _segmentTimes = new();

    // Chain head. Only changed under _gate, after the line is on disk.
    private long _lastSequence;
    private string _lastHash;
    private bool _mayBeTorn;

    public ChainedJsonLinesLog(string name, StorageOptions options, TimeProvider clock, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        Name = name;
        _hasher = new AuditChainHasher(options.AuditHmacKey);
        _segments = new AuditLogSegments(name, options, clock, _hasher, logger);
        _flushToDisk = options.FlushAuditToDisk;

        _segments.TerminateTornLine();
        (_lastSequence, _lastHash) = _segments.FindChainHead();
        _segments.ApplyRetention();

        // Shipped with the application logs, this lets someone off the host notice that the newest entries were
        // removed while the service was stopped (the chain itself cannot show that).
        Log.ChainHead(logger, name, _lastSequence, _lastHash);
    }

    public string Name { get; }

    public Task AppendAsync(byte[] payload, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return AppendAsync([payload]);
    }

    /// <summary>
    /// Appends entries in order, contiguously, and returns once they are on disk. Group commit: callers queue their
    /// entries, and whoever holds the gate next writes everything queued in one write and one flush, so concurrent
    /// badge reads share an fsync instead of waiting for one each. Not cancellable once queued: the entry may already
    /// be part of another caller's write, and a half-recorded audit trail is worse than a slow response.
    /// </summary>
    public async Task AppendAsync(IReadOnlyList<byte[]> payloads)
    {
        var appended = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _queued.Enqueue((payloads, appended));

        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!appended.Task.IsCompleted)
            {
                WriteQueuedLocked();
            }
        }
        finally
        {
            _gate.Release();
        }

        await appended.Task.ConfigureAwait(false);
    }

    private void WriteQueuedLocked()
    {
        var batch = new List<(IReadOnlyList<byte[]> Payloads, TaskCompletionSource Appended)>();
        while (_queued.TryDequeue(out var item))
        {
            batch.Add(item);
        }

        try
        {
            WriteLocked(batch.SelectMany(b => b.Payloads).ToList());
        }
        catch (Exception ex)
        {
            batch.ForEach(b => b.Appended.SetException(ex));
            return;
        }

        batch.ForEach(b => b.Appended.SetResult());
    }

    /// <summary>
    /// Returns the matching entries newest first. Streams every segment that may hold entries in
    /// [<paramref name="from"/>, <paramref name="to"/>) and keeps only the requested page in memory (see
    /// <see cref="NewestFirstPage{T}"/>). Archived segments are immutable, so their time range is remembered after
    /// the first scan and a segment entirely outside the range is not read again.
    /// </summary>
    public async Task<PagedResult<T>> QueryAsync<TRecord, T>(
        Func<TRecord, T> map,
        Func<T, bool> matches,
        Func<T, DateTimeOffset> occurredAt,
        DateTimeOffset? from,
        DateTimeOffset? to,
        PageRequest page,
        CancellationToken cancellationToken)
    {
        var (segments, _) = await OpenSegmentsAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ForgetRemovedSegments(segments);
            var result = new NewestFirstPage<T>(page);
            long position = 0;
            foreach (var segment in segments)
            {
                var isArchived = segment.Path != _segments.ActivePath;
                var stamp = (segment.Stream.Length, File.GetLastWriteTimeUtc(segment.Path));
                if (isArchived
                    && _segmentTimes.TryGetValue(segment.Path, out var known)
                    && known.Stamp == stamp
                    && !known.Range.Overlaps(from, to))
                {
                    continue;
                }

                var range = SegmentTimeRange.Empty;
                await foreach (var line in _segments.ReadLinesAsync([segment], includeRaw: false, cancellationToken).ConfigureAwait(false))
                {
                    if (line.Kind != AuditLineKind.Chained
                        || line.Data.Deserialize<TRecord>(StorageJson.Options) is not { } record)
                    {
                        continue;
                    }

                    var item = map(record);
                    var at = occurredAt(item);
                    range = range.Including(at);
                    position++;
                    if (matches(item))
                    {
                        result.Add(item, at, position);
                    }
                }

                if (isArchived)
                {
                    _segmentTimes[segment.Path] = (stamp, range);
                }
            }

            return result.ToResult();
        }
        finally
        {
            foreach (var (_, stream) in segments)
            {
                await stream.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    public async Task<AuditChainReport> VerifyAsync(CancellationToken cancellationToken)
    {
        var (segments, expectedLast) = await OpenSegmentsAsync(cancellationToken).ConfigureAwait(false);
        var anchor = _segments.ReadAnchor();
        long entries = 0, skipped = 0;
        long? first = null, last = null;
        string? head = null;
        var anchored = false;

        AuditChainReport Broken(string problem) => new(Name, false, entries, skipped, first, last, head, problem);

        if (anchor is not null && !_hasher.IsValid(anchor))
        {
            return Broken("The retention anchor does not match its signature; it was modified.");
        }

        await foreach (var line in _segments.ReadLinesAsync(segments, includeRaw: true, cancellationToken).ConfigureAwait(false))
        {
            switch (line.Kind)
            {
                case AuditLineKind.Corrupt:
                    skipped++;
                    continue;

                case AuditLineKind.Unchained:
                    return Broken($"{line.Location}: unchained entry; this service never writes one.");
            }

            if (head is null)
            {
                // The oldest entry must start the chain or continue from where retention cut it.
                anchored = (line.Sequence == 1 && line.Previous == AuditChainHasher.EmptyHash)
                    || (anchor is not null && line.Sequence == anchor.Sequence + 1 && line.Previous == anchor.Hash);
            }
            else if (line.Sequence != last + 1 || !string.Equals(line.Previous, head, StringComparison.Ordinal))
            {
                return Broken($"{line.Location}: entry {line.Sequence} does not follow entry {last}; entries were removed, inserted or reordered.");
            }

            if (!_hasher.IsValid(line.Sequence, line.Previous!, line.RawData!, line.Hash!))
            {
                return Broken($"{line.Location}: entry {line.Sequence} does not match its hash; it was modified.");
            }

            // A crash during retention can leave the anchor pointing at an entry that is still on disk.
            anchored |= anchor is not null && line.Sequence == anchor.Sequence && line.Hash == anchor.Hash;

            first ??= line.Sequence;
            last = line.Sequence;
            head = line.Hash;
            entries++;
        }

        if (first is not null && !anchored)
        {
            return Broken($"The log starts at entry {first}, not at entry 1 or after the retention anchor; the oldest entries were removed.");
        }

        if (first is null && anchor is not null)
        {
            head = anchor.Hash;
            last = anchor.Sequence;
        }

        if ((last ?? 0) < expectedLast)
        {
            return Broken($"The log ends at entry {last ?? 0} but this process has written up to entry {expectedLast}; the newest entries were removed.");
        }

        return new AuditChainReport(Name, true, entries, skipped, first, last, head, null);
    }

    public void Dispose() => _gate.Dispose();

    private void WriteLocked(List<byte[]> payloads)
    {
        if (payloads.Count == 0)
        {
            return;
        }

        var buffer = new ArrayBufferWriter<byte>();
        var sequence = _lastSequence;
        var hash = _lastHash;
        foreach (var payload in payloads)
        {
            sequence++;
            var next = _hasher.Compute(sequence, hash, payload);
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                writer.WriteNumber("seq", sequence);
                writer.WriteString("prev", hash);
                writer.WriteString("hash", next);
                writer.WritePropertyName("data");
                writer.WriteRawValue(payload, skipInputValidation: true);
                writer.WriteEndObject();
            }

            buffer.Write(NewLine);
            hash = next;
        }

        try
        {
            if (_mayBeTorn)
            {
                _segments.TerminateTornLine();
                _mayBeTorn = false;
            }

            _segments.RotateIfFull(_lastSequence);
            using (var stream = new FileStream(
                _segments.ActivePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
            {
                stream.Write(buffer.WrittenSpan);
                stream.Flush(flushToDisk: _flushToDisk);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Part of the batch may have reached the disk. Resynchronise the head with what is actually there.
            _mayBeTorn = true;
            (_lastSequence, _lastHash) = _segments.FindChainHead();
            throw;
        }

        _lastSequence = sequence;
        _lastHash = hash;
    }

    /// <summary>Drops remembered time ranges of segments that retention has deleted.</summary>
    private void ForgetRemovedSegments(List<(string Path, FileStream Stream)> segments)
    {
        foreach (var path in _segmentTimes.Keys.Except(segments.Select(s => s.Path)))
        {
            _segmentTimes.TryRemove(path, out _);
        }
    }

    /// <summary>
    /// Opens every segment under the gate, so that a concurrent rotation cannot make a reader miss or repeat
    /// a segment. Also returns the head sequence at that moment.
    /// </summary>
    private async Task<(List<(string Path, FileStream Stream)> Segments, long LastSequence)> OpenSegmentsAsync(
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return (_segments.OpenAll(), _lastSequence);
        }
        finally
        {
            _gate.Release();
        }
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 3104, Level = LogLevel.Information, Message = "Audit log {Log} chain head: entry {Sequence}, hash {Hash}")]
        public static partial void ChainHead(ILogger logger, string log, long sequence, string hash);
    }

    /// <summary>Earliest and latest timestamp in a segment; both <c>null</c> when it holds no readable entry.</summary>
    private readonly record struct SegmentTimeRange(DateTimeOffset? Earliest, DateTimeOffset? Latest)
    {
        public static SegmentTimeRange Empty => default;

        public SegmentTimeRange Including(DateTimeOffset at) =>
            new(Earliest is { } e && e <= at ? e : at, Latest is { } l && l >= at ? l : at);

        /// <summary>Whether any entry may fall in the half-open filter range [<paramref name="from"/>, <paramref name="to"/>).</summary>
        public bool Overlaps(DateTimeOffset? from, DateTimeOffset? to) =>
            Earliest is { } earliest && Latest is { } latest
            && (from is null || latest >= from)
            && (to is null || earliest < to);
    }
}
