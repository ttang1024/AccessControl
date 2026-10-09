using System.Text.Json;
using AccessControl.Application.Abstractions;
using AccessControl.Infrastructure.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AccessControl.Infrastructure.Persistence;

/// <summary>
/// Configuration-change trail in <c>changes*.jsonl</c> (hash-chained, rotated). Written by
/// <see cref="DocumentStore.CommitAsync"/> inside the commit gate, before the change is persisted or visible.
/// </summary>
internal sealed class JsonLinesChangeLog(
    IOptions<StorageOptions> options,
    TimeProvider clock,
    ILogger<JsonLinesChangeLog> logger)
    : IChangeAuditLog, IDisposable
{
    internal ChainedJsonLinesLog Log { get; } = new("changes", options.Value, clock, logger);

    public Task AppendAsync(IReadOnlyList<ChangeRecord> records) =>
        Log.AppendAsync(records.Select(r => JsonSerializer.SerializeToUtf8Bytes(r, StorageJson.Options)).ToList());

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
