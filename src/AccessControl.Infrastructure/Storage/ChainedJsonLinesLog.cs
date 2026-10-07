using System.Buffers;
using System.Runtime.CompilerServices;
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
/// and the chain continues in a new file. Lines written before chaining existed (no <c>seq</c>) are still readable
/// and are reported as legacy by verification.
/// </para>
/// <para>
/// Appends are serialized and fully written (optionally fsync'd) before returning. A torn final line from a
/// crash is terminated on startup and skipped on read; the chain continues from the last complete entry.
/// </para>
/// </summary>
internal sealed class ChainedJsonLinesLog : IDisposable
{
    private static readonly byte[] NewLine = "\n"u8.ToArray();

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly AuditLogSegments _segments;
    private readonly AuditChainHasher _hasher;
    private readonly bool _flushToDisk;

    // Chain head. Only changed under _gate, after the line is on disk.
    private long _lastSequence;
    private string _lastHash;
    private bool _mayBeTorn;

    public ChainedJsonLinesLog(string name, StorageOptions options, TimeProvider clock, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        Name = name;
        _segments = new AuditLogSegments(name, options, clock, logger);
        _hasher = new AuditChainHasher(options.AuditHmacKey);
        _flushToDisk = options.FlushAuditToDisk;

        _segments.TerminateTornLine();
        (_lastSequence, _lastHash) = _segments.FindChainHead();
        _segments.ApplyRetention();
    }

    public string Name { get; }

    /// <summary>Appends entries in order as one write. Synchronous: used inside the store's commit lock.</summary>
    public void Append(IReadOnlyList<byte[]> payloads)
    {
        _gate.Wait();
        try
        {
            WriteLocked(payloads);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task AppendAsync(byte[] payload, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Not cancellable past this point: a half-written audit line is worse than a slow response.
            WriteLocked([payload]);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Every readable entry's payload, oldest first, across all segments.</summary>
    public async IAsyncEnumerable<JsonElement> ReadAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var (segments, _) = await OpenSegmentsAsync(cancellationToken).ConfigureAwait(false);
        await foreach (var line in _segments.ReadLinesAsync(segments, includeRaw: false, cancellationToken).ConfigureAwait(false))
        {
            if (line.Kind != AuditLineKind.Corrupt)
            {
                yield return line.Data;
            }
        }
    }

    /// <summary>
    /// Scans every entry and returns the matching ones newest first. Sorted explicitly so clock adjustments cannot
    /// reorder results, and stably on the reversed list so entries with equal timestamps stay newest-appended first.
    /// </summary>
    public async Task<PagedResult<T>> QueryAsync<TRecord, T>(
        Func<TRecord, T> map,
        Func<T, bool> matches,
        Func<T, DateTimeOffset> occurredAt,
        PageRequest page,
        CancellationToken cancellationToken)
    {
        var found = new List<T>();
        await foreach (var data in ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            if (data.Deserialize<TRecord>(StorageJson.Options) is not { } record)
            {
                continue;
            }

            var item = map(record);
            if (matches(item))
            {
                found.Add(item);
            }
        }

        found.Reverse();
        return PagedResult.Create(found.OrderByDescending(occurredAt), page);
    }

    public async Task<AuditChainReport> VerifyAsync(CancellationToken cancellationToken)
    {
        var (segments, expectedLast) = await OpenSegmentsAsync(cancellationToken).ConfigureAwait(false);
        long entries = 0, legacy = 0, skipped = 0;
        long? first = null, last = null;
        string? head = null;

        AuditChainReport Broken(string problem) => new(Name, false, entries, legacy, skipped, first, last, problem);

        await foreach (var line in _segments.ReadLinesAsync(segments, includeRaw: true, cancellationToken).ConfigureAwait(false))
        {
            switch (line.Kind)
            {
                case AuditLineKind.Corrupt:
                    skipped++;
                    continue;

                case AuditLineKind.Legacy when head is not null:
                    return Broken($"{line.Location}: unchained entry after the chain started.");

                case AuditLineKind.Legacy:
                    legacy++;
                    continue;
            }

            // The oldest surviving entry anchors the chain (older segments may have been removed by retention).
            if (head is not null && (line.Sequence != last + 1 || !string.Equals(line.Previous, head, StringComparison.Ordinal)))
            {
                return Broken($"{line.Location}: entry {line.Sequence} does not follow entry {last}; entries were removed, inserted or reordered.");
            }

            if (!_hasher.IsValid(line.Sequence, line.Previous!, line.RawData!, line.Hash!))
            {
                return Broken($"{line.Location}: entry {line.Sequence} does not match its hash; it was modified.");
            }

            first ??= line.Sequence;
            last = line.Sequence;
            head = line.Hash;
            entries++;
        }

        if ((last ?? 0) < expectedLast)
        {
            return Broken($"The log ends at entry {last ?? 0} but this process has written up to entry {expectedLast}; the newest entries were removed.");
        }

        return new AuditChainReport(Name, true, entries, legacy, skipped, first, last, null);
    }

    public void Dispose() => _gate.Dispose();

    private void WriteLocked(IReadOnlyList<byte[]> payloads)
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
        catch (IOException)
        {
            // Part of the batch may have reached the disk. Resynchronise the head with what is actually there.
            _mayBeTorn = true;
            (_lastSequence, _lastHash) = _segments.FindChainHead();
            throw;
        }

        _lastSequence = sequence;
        _lastHash = hash;
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
}
