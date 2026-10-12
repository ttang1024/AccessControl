using System.Diagnostics.Metrics;
using AccessControl.Application.Abstractions;
using AccessControl.Application.Audit;
using AccessControl.Application.Credentials;
using AccessControl.Application.Errors;
using AccessControl.Domain.Access;
using AccessControl.Domain.Credentials;
using Microsoft.Extensions.Logging;

namespace AccessControl.Application.Access;

/// <summary>A badge read reported by a door controller.</summary>
public sealed record AccessRequest(Guid DoorId, string? CardNumber);

public sealed record AccessResponse(Guid EventId, bool Granted, AccessDecisionReason Reason, DateTimeOffset EvaluatedAt);

/// <param name="CardNumber">Masked display form (see <see cref="CardNumberMask"/>); the number itself is never recorded.</param>
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
        new(e.Id, e.OccurredAt, e.DoorId, e.CardDisplay, e.CredentialId, e.CardholderId, e.Granted, e.Reason);
}

public sealed partial class AccessService(
    IDoorRepository doors,
    ICredentialRepository credentials,
    ICardholderRepository cardholders,
    IAccessGroupRepository accessGroups,
    IScheduleRepository schedules,
    ICardNumberProtector protector,
    IAccessEventLog eventLog,
    AuditQueryWindow window,
    TimeProvider clock,
    ILogger<AccessService> logger)
{
    /// <summary>Meter name for <c>dotnet-counters</c> or an OpenTelemetry exporter.</summary>
    public const string MeterName = "AccessControl.Access";

    /// <summary>Raw, unparseable card data is truncated to this length, then masked, before it is audited.</summary>
    private const int MaxRawCardLength = 64;

    private static readonly Meter Meter = new(MeterName);

    private static readonly Counter<long> Decisions = Meter.CreateCounter<long>(
        "accesscontrol.access.decisions", description: "Audited badge-read decisions, by outcome and reason.");

    private static readonly Histogram<double> Duration = Meter.CreateHistogram<double>(
        "accesscontrol.access.duration", unit: "ms", description: "Time to evaluate and audit a badge read.");

    /// <summary>
    /// Evaluates a badge read and records the outcome. Every evaluated request is audited,
    /// including unknown and malformed card numbers. An unknown door is a configuration error
    /// on the controller and is rejected (404) without an audit entry.
    /// </summary>
    public async Task<AccessResponse> RequestAccessAsync(AccessRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var started = clock.GetTimestamp();
        var now = clock.GetUtcNow();
        var door = await doors.GetRequiredAsync(request.DoorId, ResourceNames.Door, ct).ConfigureAwait(false);

        CardFingerprint? card = CardNumber.TryParse(request.CardNumber, out var cardNumber) ? protector.Protect(cardNumber) : null;
        var credential = card is { } presented
            ? await credentials.FindByCardAsync(presented, ct).ConfigureAwait(false)
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
            card?.Digest,
            card is { } c ? CardNumberMask.Display(c.Hint) : Sanitize(request.CardNumber),
            credential?.Id,
            cardholder?.Id,
            decision.IsGranted,
            decision.Reason);

        // The event is written before the response is returned: a grant that cannot be audited
        // surfaces as a failure, and the controller must treat any failure as a denial.
        await eventLog.AppendAsync(accessEvent, ct).ConfigureAwait(false);

        // Card numbers are never logged or stored: for most card technologies the number is all an attacker needs
        // to clone a card. The event id links this log line to the audit entry.
        Log.AccessDecided(logger, decision.IsGranted ? "granted" : "denied", door.Id, decision.Reason, accessEvent.Id);
        Decisions.Add(
            1,
            new KeyValuePair<string, object?>("outcome", decision.IsGranted ? "granted" : "denied"),
            new KeyValuePair<string, object?>("reason", decision.Reason.ToString()));
        Duration.Record(clock.GetElapsedTime(started).TotalMilliseconds);

        return new AccessResponse(accessEvent.Id, decision.IsGranted, decision.Reason, now);
    }

    public async Task<PagedResult<AccessEventView>> QueryEventsAsync(
        AccessEventFilter filter, PageRequest page, CancellationToken ct) =>
        (await eventLog
            .QueryAsync(filter with { From = window.StartOf(filter.From, filter.To) }, page.EnsureAuditDepth(), ct)
            .ConfigureAwait(false))
        .Map(AccessEventView.From);

    private static string Sanitize(string? raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return string.Empty;
        }

        // Masked like a card number: unreadable input may still be most of one (e.g. a stray separator).
        return CardNumberMask.Invalid(new string(raw.Where(c => !char.IsControl(c)).Take(MaxRawCardLength).ToArray()));
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 1000, Level = LogLevel.Information, Message = "Access {Outcome} at door {DoorId}: {Reason} (event {EventId})")]
        public static partial void AccessDecided(ILogger logger, string outcome, Guid doorId, AccessDecisionReason reason, Guid eventId);
    }
}
