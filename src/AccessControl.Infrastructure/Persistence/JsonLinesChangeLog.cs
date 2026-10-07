using System.Text.Json;
using AccessControl.Application.Abstractions;
using AccessControl.Infrastructure.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AccessControl.Infrastructure.Persistence;

/// <summary>
/// Configuration-change trail in <c>changes*.jsonl</c> (hash-chained, rotated). Written by
/// <see cref="DocumentStore.Commit"/> inside the commit lock, before the change is persisted or visible.
/// </summary>
internal sealed class JsonLinesChangeLog(
    IOptions<StorageOptions> options,
    TimeProvider clock,
    ILogger<JsonLinesChangeLog> logger)
    : IChangeAuditLog, IDisposable
{
    private readonly ChainedJsonLinesLog _log = new("changes", options.Value, clock, logger);

    internal ChainedJsonLinesLog Log => _log;

    public void Append(IReadOnlyList<ChangeRecord> records) =>
        _log.Append(records.Select(r => JsonSerializer.SerializeToUtf8Bytes(r, StorageJson.Options)).ToList());

    public Task<PagedResult<ChangeAuditEntry>> QueryAsync(
        ChangeAuditFilter filter, PageRequest page, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(filter);
        return _log.QueryAsync<ChangeRecord, ChangeAuditEntry>(
            r => new ChangeAuditEntry(
                r.Id, r.OccurredAt, r.Actor, r.CommitId, r.Collection, r.EntityId, r.Kind, r.Version, r.Before, r.After),
            filter.Matches,
            e => e.OccurredAt,
            page,
            cancellationToken);
    }

    public void Dispose() => _log.Dispose();
}
