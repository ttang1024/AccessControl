namespace AccessControl.Domain.Access;

/// <summary>
/// Immutable audit record of one badge request. Written for every evaluated request,
/// granted or denied. The card number is recorded even when it matches no credential,
/// so that unknown-card attempts are traceable.
/// </summary>
public sealed record AccessEvent(
    Guid Id,
    DateTimeOffset OccurredAt,
    Guid DoorId,
    string CardNumber,
    Guid? CredentialId,
    Guid? CardholderId,
    bool Granted,
    AccessDecisionReason Reason);
