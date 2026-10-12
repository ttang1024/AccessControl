using System.Buffers;
using System.Collections.Concurrent;
using System.Text.Json;
using AccessControl.Application.Abstractions;
using Microsoft.Extensions.Logging;

namespace AccessControl.Infrastructure.Storage;

/// <summary>The newest entry of a chain: its sequence number and hash.</summary>
internal sealed record ChainHead(long Sequence, string Hash);

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
/// Appends are serialized and fully written (optionally fsync'd) before returning. A failed append is cut off the
/// file again, so the file never holds a partial batch; a torn final line from a crash is terminated on startup and
/// skipped on read, and the chain continues from the last complete entry.
/// </para>
/// </summary>
internal sealed partial class ChainedJsonLinesLog : IDisposable
{
    private static readonly byte[] NewLine = "\n"u8.ToArray();

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly ConcurrentQueue<(IReadOnlyList<byte[]> Payloads, TaskCompletionSource<long> Appended)> _queued = new();
    private readonly AuditLogSegments _segments;
    private readonly AuditChainHasher _hasher;
    private readonly bool _flushToDisk;
    private readonly ILogger _logger;

    // Time range of each archived segment, by path; the stamp (length, last write) detects a replaced file.
    private readonly ConcurrentDictionary<string, ((long Length, DateTime LastWrite) Stamp, SegmentTimeRange Range)> _segmentTimes = new();

    // Only replaced under _gate, after the line is on disk. Read lock-free (e.g. by the store's checkpoint).
    private ChainHead _head;
    private bool _mayBeTorn;

    /// <param name="directory">Held for the life of the log, so no other process writes the same files.</param>
    public ChainedJsonLinesLog(string name, DataDirectoryLock directory, StorageOptions options, TimeProvider clock, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(directory);
        ArgumentNullException.ThrowIfNull(options);
        Name = name;
        _logger = logger;
        _hasher = new AuditChainHasher(options.AuditHmacKey);
        _segments = new AuditLogSegments(name, directory.DirectoryPath, options, clock, _hasher, logger);
        _flushToDisk = options.FlushAuditToDisk;

        _segments.TerminateTornLine();
        _head = _segments.FindChainHead();
        _segments.ApplyRetention();

        // Shipped with the application logs, this lets someone off the host notice that the newest entries were
        // removed while the service was stopped (the chain itself cannot show that).
        Log.ChainHead(logger, name, _head.Sequence, _head.Hash);
    }

    public string Name { get; }

    /// <summary>The newest entry on disk.</summary>
    public ChainHead Head => Volatile.Read(ref _head);

    /// <summary>Appends one entry and returns its sequence number once it is on disk.</summary>
    public Task<long> AppendAsync(byte[] payload, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return AppendAsync([payload]);
    }

    /// <summary>
    /// Appends entries in order, contiguously, and returns the sequence number of the last one once they are on disk.
    /// Group commit: callers queue their entries, and whoever holds the gate next writes everything queued in one write
    /// and one flush, so concurrent badge reads share an fsync instead of waiting for one each. Not cancellable once
    /// queued: the entry may already be part of another caller's write, and a half-recorded audit trail is worse than
    /// a slow response.
    /// </summary>
    public async Task<long> AppendAsync(IReadOnlyList<byte[]> payloads)
    {
        var appended = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);
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

        return await appended.Task.ConfigureAwait(false);
    }

    /// <summary>
    /// The verified entries after <paramref name="sequence"/>, oldest first, for replaying a checkpoint. The first one
    /// must follow <paramref name="hash"/> and each must follow the previous one with a valid hash: replaying an
    /// altered or incomplete history would silently install configuration nobody made, so any break throws.
    /// A torn final line from a crash is skipped. Startup only: callers must not append concurrently.
    /// </summary>
    /// <exception cref="InvalidDataException">The entries after <paramref name="sequence"/> are missing or broken.</exception>
    public IEnumerable<(long Sequence, JsonElement Data)> ReadAfter(long sequence, string hash)
    {
        var segments = _segments.OpenAll(afterSequence: sequence);
        var (expectedSequence, expectedPrevious) = (sequence + 1, hash);
        foreach (var line in _segments.ReadLinesAsync(segments, CancellationToken.None).ToBlockingEnumerable())
        {
            if (line.Kind != AuditLineKind.Chained || line.Sequence <= sequence)
            {
                continue;
            }

            if (line.Sequence != expectedSequence
                || !string.Equals(line.Previous, expectedPrevious, StringComparison.Ordinal)
                || !_hasher.IsValid(line.Sequence, line.Previous!, line.RawData!, line.Hash!))
            {
                throw new InvalidDataException(
                    $"{Name}: {line.Location} does not continue the chain from entry {expectedSequence - 1}; " +
                    "the entries needed to recover the store are missing or were altered. Run audit/verify.");
            }

            yield return (line.Sequence, line.Data);
            (expectedSequence, expectedPrevious) = (line.Sequence + 1, line.Hash!);
        }

        if (expectedSequence - 1 < Head.Sequence)
        {
            throw new InvalidDataException(
                $"{Name}: entries {expectedSequence} to {Head.Sequence} could not be read; cannot recover the store.");
        }
    }

    private void WriteQueuedLocked()
    {
        var batch = new List<(IReadOnlyList<byte[]> Payloads, TaskCompletionSource<long> Appended)>();
        while (_queued.TryDequeue(out var item))
        {
            batch.Add(item);
        }

        long first;
        try
        {
            first = WriteLocked(batch.SelectMany(b => b.Payloads).ToList());
        }
        catch (Exception ex)
        {
            batch.ForEach(b => b.Appended.SetException(ex));
            return;
        }

        var last = first - 1;
        foreach (var (payloads, appended) in batch)
        {
            last += payloads.Count;
            appended.SetResult(last);
        }
    }

    /// <summary>
    /// Returns the matching entries newest first. Streams every segment that may hold entries in
    /// [<paramref name="from"/>, <paramref name="to"/>) and keeps only the requested page in memory (see
    /// <see cref="NewestFirstPage{T}"/>). Archived segments are immutable, so their time range is remembered after
    /// the first scan and a segment entirely outside the range is not read again. Lines whose hash does not match
    /// their content are left out (and logged): a query never presents an altered entry as genuine.
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
        ForgetRemovedSegments(segments);
        var result = new NewestFirstPage<T>(page);
        long position = 0;

        // ReadLinesAsync disposes each segment's stream; the ones skipped here are disposed below.
        var unread = new List<FileStream>();
        try
        {
            foreach (var segment in segments)
            {
                var isArchived = segment.Path != _segments.ActivePath;
                var stamp = (segment.Stream.Length, File.GetLastWriteTimeUtc(segment.Path));
                if (isArchived
                    && _segmentTimes.TryGetValue(segment.Path, out var known)
                    && known.Stamp == stamp
                    && !known.Range.Overlaps(from, to))
                {
                    unread.Add(segment.Stream);
                    continue;
                }

                var range = SegmentTimeRange.Empty;
                await foreach (var line in _segments.ReadLinesAsync([segment], cancellationToken).ConfigureAwait(false))
                {
                    if (line.Kind != AuditLineKind.Chained)
                    {
                        continue;
                    }

                    if (!_hasher.IsValid(line.Sequence, line.Previous!, line.RawData!, line.Hash!))
                    {
                        Log.TamperedLineSkipped(_logger, line.Location);
                        continue;
                    }

                    if (line.Data.Deserialize<TRecord>(StorageJson.Options) is not { } record)
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
            foreach (var stream in unread)
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
            foreach (var (_, stream) in segments)
            {
                await stream.DisposeAsync().ConfigureAwait(false);
            }

            return Broken("The retention anchor does not match its signature; it was modified.");
        }

        await foreach (var line in _segments.ReadLinesAsync(segments, cancellationToken).ConfigureAwait(false))
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

    /// <summary>Writes the entries as one block and returns the first one's sequence number.</summary>
    private long WriteLocked(List<byte[]> payloads)
    {
        var start = Head;
        if (payloads.Count == 0)
        {
            return start.Sequence + 1;
        }

        var buffer = new ArrayBufferWriter<byte>();
        var sequence = start.Sequence;
        var hash = start.Hash;
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

        if (_mayBeTorn)
        {
            _segments.TerminateTornLine();
            _mayBeTorn = false;
        }

        _segments.RotateIfFull(start.Sequence);

        using (var stream = new FileStream(
            _segments.ActivePath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
        {
            var originalLength = stream.Seek(0, SeekOrigin.End);
            try
            {
                stream.Write(buffer.WrittenSpan);
                stream.Flush(flushToDisk: _flushToDisk);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Part of the batch may have reached the disk. Cut it off again, so the file still ends at the head
                // and nobody can mistake an entry the caller was told failed for one that was recorded.
                Truncate(stream, originalLength);
                throw;
            }
        }

        Volatile.Write(ref _head, new ChainHead(sequence, hash));
        return start.Sequence + 1;
    }

    private void Truncate(FileStream stream, long length)
    {
        try
        {
            stream.SetLength(length);
            stream.Flush(flushToDisk: _flushToDisk);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Could not cut the partial write off: rescan for the real head and end the torn line before the next append.
            Log.TruncateFailed(_logger, ex, _segments.ActivePath);
            _mayBeTorn = true;
            Volatile.Write(ref _head, _segments.FindChainHead());
        }
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
            return (_segments.OpenAll(), Head.Sequence);
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

        [LoggerMessage(EventId = 3105, Level = LogLevel.Warning, Message = "Audit query skipped {Location}: its hash does not match its content (run audit/verify)")]
        public static partial void TamperedLineSkipped(ILogger logger, string location);

        [LoggerMessage(EventId = 3106, Level = LogLevel.Error, Message = "Could not remove a failed append from {Path}; the partial line will be terminated before the next append")]
        public static partial void TruncateFailed(ILogger logger, Exception exception, string path);
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
