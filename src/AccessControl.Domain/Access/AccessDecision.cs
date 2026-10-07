namespace AccessControl.Domain.Access;

/// <summary>Why a request was granted or denied. Values are persisted by name — append, never rename.</summary>
public enum AccessDecisionReason
{
    Granted,
    DoorInLockdown,
    UnknownCredential,
    CredentialNotActive,
    CredentialExpired,
    CardholderNotFound,
    CardholderDisabled,
    CardholderOutsideValidityPeriod,
    NoPermissionForDoor,
    OutsideSchedule,
}

public sealed record AccessDecision(bool IsGranted, AccessDecisionReason Reason)
{
    public static readonly AccessDecision Grant = new(true, AccessDecisionReason.Granted);

    public static AccessDecision Deny(AccessDecisionReason reason) =>
        reason == AccessDecisionReason.Granted
            ? throw new ArgumentException("A denial needs a denial reason.", nameof(reason))
            : new AccessDecision(false, reason);
}
