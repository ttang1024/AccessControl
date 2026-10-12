using System.Text.Json;
using AccessControl.Application.Abstractions;
using AccessControl.Infrastructure.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AccessControl.Infrastructure.Persistence;

/// <summary>
/// Configuration-change trail in <c>changes*.jsonl</c> (hash-chained, rotated), and the store's write-ahead log:
/// <see cref="DocumentStore.CommitAsync"/> commits by appending here, and startup replays it after the checkpoint.
/// </summary>
internal sealed class JsonLinesChangeLog(
    IOptions<StorageOptions> options,
    DataDirectoryLock directory,
    TimeProvider clock,
    ILogger<JsonLinesChangeLog> logger)
    : IChangeAuditLog, IDisposable
{
    internal ChainedJsonLinesLog Log { get; } = new("changes", directory, options.Value, clock, logger);

    /// <summary>Appends one commit's entries contiguously; returns the last one's sequence number once on disk.</summary>
    public Task<long> AppendAsync(IReadOnlyList<ChangeRecord> records) =>
        Log.AppendAsync(records.Select(r => JsonSerializer.SerializeToUtf8Bytes(r, StorageJson.Options)).ToList());

    /// <summary>The verified entries after <paramref name="sequence"/>, oldest first (see <see cref="ChainedJsonLinesLog.ReadAfter"/>).</summary>
    public IEnumerable<(long Sequence, ChangeRecord Record)> ReadAfter(long sequence, string hash) =>
        Log.ReadAfter(sequence, hash).Select(e => (
            e.Sequence,
            e.Data.Deserialize<ChangeRecord>(StorageJson.Options)
                ?? throw new InvalidDataException($"Change log entry {e.Sequence} is empty.")));

    public Task<PagedResult<ChangeAuditEntry>> QueryAsync(
        ChangeAuditFilter filter, PageRequest page, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(filter);
        return Log.QueryAsync<ChangeRecord, ChangeAuditEntry>(
            r => new ChangeAuditEntry(
                r.Id, r.OccurredAt, r.Actor, r.CommitId, r.Collection, r.EntityId, r.Kind, r.Version, r.Before, r.After),
            filter.Matches,
            e => e.OccurredAt,
            filter.From,
            filter.To,
            page,
            cancellationToken);
    }

    public void Dispose() => Log.Dispose();
}
