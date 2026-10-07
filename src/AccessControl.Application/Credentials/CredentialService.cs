using AccessControl.Application.Abstractions;
using AccessControl.Application.Errors;
using AccessControl.Domain.Credentials;

namespace AccessControl.Application.Credentials;

public sealed record IssueCredentialRequest(string? CardNumber, DateTimeOffset? ExpiresAt);

public sealed record ChangeCredentialExpiryRequest(DateTimeOffset? ExpiresAt);

public sealed record CredentialView(
    Guid Id,
    Guid CardholderId,
    string CardNumber,
    CredentialStatus Status,
    DateTimeOffset IssuedAt,
    DateTimeOffset? ExpiresAt)
{
    public static CredentialView From(Credential c) =>
        new(c.Id, c.CardholderId, c.CardNumber.Value, c.Status, c.IssuedAt, c.ExpiresAt);
}

public sealed class CredentialService(
    ICredentialRepository credentials,
    ICardholderRepository cardholders,
    IUnitOfWork unitOfWork,
    TimeProvider clock)
{
    private const string Resource = "Credential";

    /// <summary>
    /// Issues a card to a cardholder. Card numbers are unique for life: the check here gives a clear
    /// error, and the store enforces the same rule atomically at commit time to close the race.
    /// </summary>
    public async Task<CredentialView> IssueAsync(Guid cardholderId, IssueCredentialRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var cardNumber = CardNumber.Parse(request.CardNumber);
        await cardholders.GetRequiredAsync(cardholderId, "Cardholder", ct).ConfigureAwait(false);

        if (await credentials.FindByCardNumberAsync(cardNumber, ct).ConfigureAwait(false) is not null)
        {
            throw ConflictException.DuplicateCardNumber(cardNumber.Value);
        }

        var credential = Credential.Issue(
            Guid.NewGuid(), cardholderId, cardNumber, clock.GetUtcNow(), request.ExpiresAt);

        credentials.Add(credential);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return CredentialView.From(credential);
    }

    public async Task<CredentialView> GetAsync(Guid id, CancellationToken ct) =>
        CredentialView.From(await credentials.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false));

    public async Task<IReadOnlyList<CredentialView>> ListForCardholderAsync(Guid cardholderId, CancellationToken ct)
    {
        await cardholders.GetRequiredAsync(cardholderId, "Cardholder", ct).ConfigureAwait(false);
        var list = await credentials.ListByCardholderAsync(cardholderId, ct).ConfigureAwait(false);
        return list.OrderBy(c => c.IssuedAt).Select(CredentialView.From).ToList();
    }

    public Task<CredentialView> SuspendAsync(Guid id, CancellationToken ct) => ModifyAsync(id, c => c.Suspend(), ct);

    public Task<CredentialView> ReinstateAsync(Guid id, CancellationToken ct) => ModifyAsync(id, c => c.Reinstate(), ct);

    public Task<CredentialView> ReportLostAsync(Guid id, CancellationToken ct) => ModifyAsync(id, c => c.ReportLost(), ct);

    public Task<CredentialView> RevokeAsync(Guid id, CancellationToken ct) => ModifyAsync(id, c => c.Revoke(), ct);

    public Task<CredentialView> ChangeExpiryAsync(Guid id, ChangeCredentialExpiryRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        return ModifyAsync(id, c => c.ChangeExpiry(request.ExpiresAt), ct);
    }

    private async Task<CredentialView> ModifyAsync(Guid id, Action<Credential> change, CancellationToken ct)
    {
        var credential = await credentials.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false);
        change(credential);
        credentials.Update(credential);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return CredentialView.From(credential);
    }
}
