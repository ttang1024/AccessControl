using AccessControl.Domain.Common;

namespace AccessControl.Domain.Credentials;

public enum CredentialStatus
{
    Active,
    Suspended,
    Lost,
    Revoked,
}

/// <summary>
/// A physical card bound to one cardholder, identified by its <see cref="CardFingerprint"/> (never the number itself).
/// <para>
/// Lifecycle: <c>Active ⇄ Suspended</c>; <c>Active|Suspended → Lost</c>; any non-revoked → <c>Revoked</c>.
/// Lost and Revoked are terminal. Card numbers are unique for life, so a lost card that turns up
/// cannot be re-enrolled; it is destroyed and a new card is issued.
/// </para>
/// </summary>
public sealed class Credential
{
    private Credential(
        Guid id,
        Guid cardholderId,
        CardFingerprint card,
        CredentialStatus status,
        DateTimeOffset issuedAt,
        DateTimeOffset? expiresAt)
    {
        Id = Guard.NotEmpty(id, "credential.id");
        CardholderId = Guard.NotEmpty(cardholderId, "cardholderId");
        Card = card.Digest is null
            ? throw DomainException.Validation("card.required", "A card is required.")
            : card;
        Status = status;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
    }

    public Guid Id { get; }

    public Guid CardholderId { get; }

    public CardFingerprint Card { get; }

    public CredentialStatus Status { get; private set; }

    public DateTimeOffset IssuedAt { get; }

    /// <summary>Exclusive expiry instant, or <c>null</c> if the card never expires.</summary>
    public DateTimeOffset? ExpiresAt { get; private set; }

    public bool IsTerminal => Status is CredentialStatus.Lost or CredentialStatus.Revoked;

    public static Credential Issue(
        Guid id, Guid cardholderId, CardFingerprint card, DateTimeOffset issuedAt, DateTimeOffset? expiresAt)
    {
        EnsureValidExpiry(expiresAt, issuedAt);
        return new Credential(id, cardholderId, card, CredentialStatus.Active, issuedAt, expiresAt);
    }

    /// <summary>Rebuilds a credential from persisted state. Not for issuing new credentials.</summary>
    public static Credential Rehydrate(
        Guid id,
        Guid cardholderId,
        CardFingerprint card,
        CredentialStatus status,
        DateTimeOffset issuedAt,
        DateTimeOffset? expiresAt) =>
        new(id, cardholderId, card, status, issuedAt, expiresAt);

    public void Suspend() => Transition(CredentialStatus.Suspended, CredentialStatus.Active);

    public void Reinstate() => Transition(CredentialStatus.Active, CredentialStatus.Suspended);

    public void ReportLost() =>
        Transition(CredentialStatus.Lost, CredentialStatus.Active, CredentialStatus.Suspended);

    public void Revoke() =>
        Transition(CredentialStatus.Revoked, CredentialStatus.Active, CredentialStatus.Suspended, CredentialStatus.Lost);

    public void ChangeExpiry(DateTimeOffset? expiresAt)
    {
        if (IsTerminal)
        {
            throw DomainException.InvalidState(
                "credential.terminal", $"A {Status} credential cannot be changed.");
        }

        EnsureValidExpiry(expiresAt, IssuedAt);
        ExpiresAt = expiresAt;
    }

    public bool IsExpiredAt(DateTimeOffset instant) => ExpiresAt is not null && instant >= ExpiresAt;

    private static void EnsureValidExpiry(DateTimeOffset? expiresAt, DateTimeOffset issuedAt)
    {
        if (expiresAt is not null && expiresAt <= issuedAt)
        {
            throw DomainException.Validation(
                "credential.invalid_expiry", "expiresAt must be later than the issue time.");
        }
    }

    private void Transition(CredentialStatus target, params CredentialStatus[] allowedFrom)
    {
        if (Array.IndexOf(allowedFrom, Status) < 0)
        {
            throw DomainException.InvalidState(
                "credential.invalid_transition", $"Cannot change a credential from {Status} to {target}.");
        }

        Status = target;
    }
}
