using System.Text.Json;
using AccessControl.Application.Abstractions;
using AccessControl.Domain.Access;
using AccessControl.Infrastructure.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AccessControl.Infrastructure.Persistence;

/// <summary>
/// Badge-read audit trail in <c>access-events*.jsonl</c> (hash-chained, rotated; see <see cref="ChainedJsonLinesLog"/>).
/// Queries scan every segment; see CLAUDE.md for the indexing limits this implies. Entries hold a card fingerprint,
/// never the card number.
/// </summary>
internal sealed class JsonLinesAccessEventLog(
    IOptions<StorageOptions> options,
    DataDirectoryLock directory,
    TimeProvider clock,
    ILogger<JsonLinesAccessEventLog> logger)
    : IAccessEventLog, IDisposable
{
    internal ChainedJsonLinesLog Log { get; } = new("access-events", directory, options.Value, clock, logger);

    public Task AppendAsync(AccessEvent accessEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(accessEvent);
        var record = new AccessEventRecord(
            accessEvent.Id, accessEvent.OccurredAt, accessEvent.DoorId, accessEvent.CardDigest, accessEvent.CardDisplay,
            accessEvent.CredentialId, accessEvent.CardholderId, accessEvent.Granted, accessEvent.Reason);
        return Log.AppendAsync(JsonSerializer.SerializeToUtf8Bytes(record, StorageJson.Options), cancellationToken);
    }

    public Task<PagedResult<AccessEvent>> QueryAsync(
        AccessEventFilter filter, PageRequest page, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(filter);
        return Log.QueryAsync<AccessEventRecord, AccessEvent>(
            r => new AccessEvent(
                r.Id, r.OccurredAt, r.DoorId, r.CardNumberDigest, r.CardDisplay,
                r.CredentialId, r.CardholderId, r.Granted, r.Reason),
            filter.Matches,
            e => e.OccurredAt,
            filter.From,
            filter.To,
            page,
            cancellationToken);
    }

    public void Dispose() => Log.Dispose();
}
