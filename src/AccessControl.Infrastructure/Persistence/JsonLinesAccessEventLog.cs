using System.Text.Json;
using AccessControl.Application.Abstractions;
using AccessControl.Domain.Access;
using AccessControl.Infrastructure.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AccessControl.Infrastructure.Persistence;

/// <summary>
/// Badge-read audit trail in <c>access-events*.jsonl</c> (hash-chained, rotated; see <see cref="ChainedJsonLinesLog"/>).
/// Queries scan every segment; see CLAUDE.md for the indexing limits this implies.
/// </summary>
internal sealed class JsonLinesAccessEventLog(
    IOptions<StorageOptions> options,
    TimeProvider clock,
    ILogger<JsonLinesAccessEventLog> logger)
    : IAccessEventLog, IDisposable
{
    private readonly ChainedJsonLinesLog _log = new("access-events", options.Value, clock, logger);

    internal ChainedJsonLinesLog Log => _log;

    public Task AppendAsync(AccessEvent accessEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(accessEvent);
        var record = new AccessEventRecord(
            accessEvent.Id, accessEvent.OccurredAt, accessEvent.DoorId, accessEvent.CardNumber,
            accessEvent.CredentialId, accessEvent.CardholderId, accessEvent.Granted, accessEvent.Reason);
        return _log.AppendAsync(JsonSerializer.SerializeToUtf8Bytes(record, StorageJson.Options), cancellationToken);
    }

    public Task<PagedResult<AccessEvent>> QueryAsync(
        AccessEventFilter filter, PageRequest page, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(filter);
        return _log.QueryAsync<AccessEventRecord, AccessEvent>(
            r => new AccessEvent(
                r.Id, r.OccurredAt, r.DoorId, r.CardNumber, r.CredentialId, r.CardholderId, r.Granted, r.Reason),
            filter.Matches,
            e => e.OccurredAt,
            page,
            cancellationToken);
    }

    public void Dispose() => _log.Dispose();
}
