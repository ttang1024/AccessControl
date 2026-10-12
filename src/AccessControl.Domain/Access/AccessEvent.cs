namespace AccessControl.Domain.Access;

/// <summary>
/// Immutable audit record of one badge request. Written for every evaluated request, granted or denied.
/// The card is recorded even when it matches no credential, so that unknown-card attempts are traceable:
/// as its fingerprint digest (the same card always gives the same digest) and a masked display form.
/// The card number itself is never recorded.
/// </summary>
/// <param name="CardDigest">Fingerprint digest of the presented card; <c>null</c> if the reader sent something that is not a card number.</param>
/// <param name="CardDisplay">Masked form for people, e.g. <c>****1234</c>, or <c>invalid:****</c> for unreadable input.</param>
public sealed record AccessEvent(
    Guid Id,
    DateTimeOffset OccurredAt,
    Guid DoorId,
    string? CardDigest,
    string CardDisplay,
    Guid? CredentialId,
    Guid? CardholderId,
    bool Granted,
    AccessDecisionReason Reason);
