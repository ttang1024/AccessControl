using AccessControl.Domain.AccessGroups;
using AccessControl.Domain.Cardholders;
using AccessControl.Domain.Credentials;
using AccessControl.Domain.Doors;
using AccessControl.Domain.Schedules;

namespace AccessControl.Domain.Access;

/// <summary>Everything the evaluator needs, loaded up front so the decision itself is pure.</summary>
/// <param name="Door">The door being requested.</param>
/// <param name="Credential">The credential matching the presented card, or <c>null</c> if none.</param>
/// <param name="Cardholder">The credential's cardholder, or <c>null</c> if missing.</param>
/// <param name="AccessGroups">The cardholder's access groups that still exist.</param>
/// <param name="Schedules">Schedules referenced by <paramref name="AccessGroups"/>, by id.</param>
/// <param name="Now">The instant the request is evaluated at.</param>
public sealed record AccessRequestContext(
    Door Door,
    Credential? Credential,
    Cardholder? Cardholder,
    IReadOnlyCollection<AccessGroup> AccessGroups,
    IReadOnlyDictionary<Guid, Schedule> Schedules,
    DateTimeOffset Now);

/// <summary>
/// Decides whether a badge request is granted. Fails closed: any missing or inconsistent data
/// results in a denial. Checks run in a fixed order so the reported reason is deterministic:
/// door mode, credential, cardholder, permission, schedule.
/// </summary>
public static class AccessEvaluator
{
    public static AccessDecision Evaluate(AccessRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Door.Mode == DoorMode.Lockdown)
        {
            return AccessDecision.Deny(AccessDecisionReason.DoorInLockdown);
        }

        var credential = context.Credential;
        if (credential is null)
        {
            return AccessDecision.Deny(AccessDecisionReason.UnknownCredential);
        }

        if (credential.Status != CredentialStatus.Active)
        {
            return AccessDecision.Deny(AccessDecisionReason.CredentialNotActive);
        }

        if (credential.IsExpiredAt(context.Now))
        {
            return AccessDecision.Deny(AccessDecisionReason.CredentialExpired);
        }

        var cardholder = context.Cardholder;
        if (cardholder is null || cardholder.Id != credential.CardholderId)
        {
            return AccessDecision.Deny(AccessDecisionReason.CardholderNotFound);
        }

        if (!cardholder.IsEnabled)
        {
            return AccessDecision.Deny(AccessDecisionReason.CardholderDisabled);
        }

        if (!cardholder.IsWithinValidityPeriod(context.Now))
        {
            return AccessDecision.Deny(AccessDecisionReason.CardholderOutsideValidityPeriod);
        }

        // Only groups the cardholder actually belongs to count, even if the caller passed more.
        var groupsForDoor = context.AccessGroups
            .Where(g => g.Covers(context.Door.Id) && cardholder.AccessGroupIds.Contains(g.Id))
            .ToList();

        if (groupsForDoor.Count == 0)
        {
            return AccessDecision.Deny(AccessDecisionReason.NoPermissionForDoor);
        }

        var inSchedule = groupsForDoor.Exists(g =>
            context.Schedules.TryGetValue(g.ScheduleId, out var schedule) && schedule.IsActiveAt(context.Now));

        return inSchedule
            ? AccessDecision.Grant
            : AccessDecision.Deny(AccessDecisionReason.OutsideSchedule);
    }
}
