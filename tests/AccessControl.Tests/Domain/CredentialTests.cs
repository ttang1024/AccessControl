using AccessControl.Domain.Common;
using AccessControl.Domain.Credentials;
using Xunit;

namespace AccessControl.Tests.Domain;

public sealed class CredentialTests
{
    private static readonly DateTimeOffset IssuedAt = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static Credential NewCredential(DateTimeOffset? expiresAt = null) =>
        Credential.Issue(Guid.NewGuid(), Guid.NewGuid(), CardFingerprint.Create(new string('A', CardFingerprint.DigestLength), ""), IssuedAt, expiresAt);

    [Fact]
    public void New_credential_is_active()
    {
        Assert.Equal(CredentialStatus.Active, NewCredential().Status);
    }

    [Fact]
    public void Suspend_and_reinstate_round_trip()
    {
        var credential = NewCredential();
        credential.Suspend();
        Assert.Equal(CredentialStatus.Suspended, credential.Status);
        credential.Reinstate();
        Assert.Equal(CredentialStatus.Active, credential.Status);
    }

    [Fact]
    public void Lost_is_terminal_except_for_revoke()
    {
        var credential = NewCredential();
        credential.ReportLost();

        Assert.True(credential.IsTerminal);
        Assert.Equal("credential.invalid_transition", Assert.Throws<DomainException>(credential.Reinstate).Code);
        Assert.Equal("credential.invalid_transition", Assert.Throws<DomainException>(credential.Suspend).Code);

        credential.Revoke();
        Assert.Equal(CredentialStatus.Revoked, credential.Status);
    }

    [Fact]
    public void Revoked_cannot_change()
    {
        var credential = NewCredential();
        credential.Revoke();

        Assert.Equal(DomainErrorKind.InvalidState, Assert.Throws<DomainException>(credential.Revoke).Kind);
        Assert.Throws<DomainException>(() => credential.ChangeExpiry(null));
    }

    [Fact]
    public void Expiry_must_be_after_issue()
    {
        var ex = Assert.Throws<DomainException>(() => NewCredential(IssuedAt));
        Assert.Equal("credential.invalid_expiry", ex.Code);
    }

    [Fact]
    public void Expiry_is_exclusive()
    {
        var expiresAt = IssuedAt.AddDays(30);
        var credential = NewCredential(expiresAt);

        Assert.False(credential.IsExpiredAt(expiresAt.AddTicks(-1)));
        Assert.True(credential.IsExpiredAt(expiresAt));
    }
}
