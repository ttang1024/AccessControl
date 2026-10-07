using AccessControl.Application.Abstractions;
using AccessControl.Domain.Access;
using AccessControl.Domain.Credentials;
using Microsoft.Extensions.Logging;

namespace AccessControl.Application.Access;

/// <summary>A badge read reported by a door controller.</summary>
public sealed record AccessRequest(Guid DoorId, string? CardNumber);

public sealed record AccessResponse(Guid EventId, bool Granted, AccessDecisionReason Reason, DateTimeOffset EvaluatedAt);

public sealed record AccessEventView(
    Guid Id,
    DateTimeOffset OccurredAt,
    Guid DoorId,
    string CardNumber,
    Guid? CredentialId,
    Guid? CardholderId,
    bool Granted,
    AccessDecisionReason Reason)
{
    public static AccessEventView From(AccessEvent e) =>
        new(e.Id, e.OccurredAt, e.DoorId, e.CardNumber, e.CredentialId, e.CardholderId, e.Granted, e.Reason);
}

public sealed partial class AccessService(
    IDoorRepository doors,
    ICredentialRepository credentials,
    ICardholderRepository cardholders,
    IAccessGroupRepository accessGroups,
    IScheduleRepository schedules,
    IAccessEventLog eventLog,
    TimeProvider clock,
    ILogger<AccessService> logger)
{
    /// <summary>Raw, unparseable card data is truncated to this length before it is audited.</summary>
    private const int MaxRawCardLength = 64;

    /// <summary>
    /// Evaluates a badge read and records the outcome. Every evaluated request is audited,
    /// including unknown and malformed card numbers. An unknown door is a configuration error
    /// on the controller and is rejected (404) without an audit entry.
    /// </summary>
    public async Task<AccessResponse> RequestAccessAsync(AccessRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var now = clock.GetUtcNow();
        var door = await doors.GetRequiredAsync(request.DoorId, "Door", ct).ConfigureAwait(false);

        var parsed = CardNumber.TryParse(request.CardNumber, out var cardNumber);
        var credential = parsed
            ? await credentials.FindByCardNumberAsync(cardNumber, ct).ConfigureAwait(false)
            : null;

        var cardholder = credential is null
            ? null
            : await cardholders.GetAsync(credential.CardholderId, ct).ConfigureAwait(false);

        var groups = cardholder is null
            ? []
            : await accessGroups.GetManyAsync(cardholder.AccessGroupIds, ct).ConfigureAwait(false);

        var scheduleList = await schedules
            .GetManyAsync(groups.Select(g => g.ScheduleId).Distinct(), ct)
            .ConfigureAwait(false);

        var decision = AccessEvaluator.Evaluate(new AccessRequestContext(
            door,
            credential,
            cardholder,
            groups,
            scheduleList.ToDictionary(s => s.Id),
            now));

        var accessEvent = new AccessEvent(
            Guid.NewGuid(),
            now,
            door.Id,
            parsed ? cardNumber.Value : Sanitize(request.CardNumber),
            credential?.Id,
            cardholder?.Id,
            decision.IsGranted,
            decision.Reason);

        // The event is written before the response is returned: a grant that cannot be audited
        // surfaces as a failure, and the controller must treat any failure as a denial.
        await eventLog.AppendAsync(accessEvent, ct).ConfigureAwait(false);

        // Card numbers are not logged: for most card technologies the number is all an attacker needs to
        // clone a card, and application logs travel further than the audit log. The event id links to it.
        Log.AccessDecided(logger, decision.IsGranted ? "granted" : "denied", door.Id, decision.Reason, accessEvent.Id);

        return new AccessResponse(accessEvent.Id, decision.IsGranted, decision.Reason, now);
    }

    public async Task<PagedResult<AccessEventView>> QueryEventsAsync(
        AccessEventFilter filter, PageRequest page, CancellationToken ct) =>
        (await eventLog.QueryAsync(filter, page, ct).ConfigureAwait(false)).Map(AccessEventView.From);

    private static string Sanitize(string? raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return string.Empty;
        }

        var cleaned = new string(raw.Where(c => !char.IsControl(c)).Take(MaxRawCardLength).ToArray());
        return $"invalid:{cleaned}";
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 1000, Level = LogLevel.Information, Message = "Access {Outcome} at door {DoorId}: {Reason} (event {EventId})")]
        public static partial void AccessDecided(ILogger logger, string outcome, Guid doorId, AccessDecisionReason reason, Guid eventId);
    }
}
