using AccessControl.Application.Abstractions;
using AccessControl.Application.Errors;
using AccessControl.Domain.Credentials;

namespace AccessControl.Application.Credentials;

public sealed record IssueCredentialRequest(string? CardNumber, DateTimeOffset? ExpiresAt);

public sealed record ChangeCredentialExpiryRequest(DateTimeOffset? ExpiresAt);

/// <param name="CardNumber">Masked (see <see cref="CardNumberMask"/>): the full number is never stored.</param>
public sealed record CredentialView(
    Guid Id,
    Guid CardholderId,
    string CardNumber,
    CredentialStatus Status,
    DateTimeOffset IssuedAt,
    DateTimeOffset? ExpiresAt,
    int Version) : IVersioned
{
    public static CredentialView From(Credential c, int version) =>
        new(c.Id, c.CardholderId, CardNumberMask.Display(c.Card.Hint), c.Status, c.IssuedAt, c.ExpiresAt, version);
}

public sealed class CredentialService(
    ICredentialRepository credentials,
    ICardholderRepository cardholders,
    ICardNumberProtector protector,
    IUnitOfWork unitOfWork,
    TimeProvider clock)
{
    private const string Resource = ResourceNames.Credential;

    /// <summary>
    /// Issues a card to a cardholder. Card numbers are unique for life and the cardholder must exist; the store
    /// enforces both atomically at commit (<c>credential.duplicate_card_number</c>, <c>cardholder.not_found</c>).
    /// </summary>
    public async Task<CredentialView> IssueAsync(Guid cardholderId, IssueCredentialRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var card = protector.Protect(CardNumber.Parse(request.CardNumber));
        var credential = Credential.Issue(Guid.NewGuid(), cardholderId, card, clock.GetUtcNow(), request.ExpiresAt);

        credentials.Add(credential);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return View(credential);
    }

    public async Task<CredentialView> GetAsync(Guid id, CancellationToken ct) =>
        View(await credentials.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false));

    public async Task<IReadOnlyList<CredentialView>> ListForCardholderAsync(Guid cardholderId, CancellationToken ct)
    {
        await cardholders.GetRequiredAsync(cardholderId, ResourceNames.Cardholder, ct).ConfigureAwait(false);
        return (await credentials.ListByCardholderAsync(cardholderId, ct).ConfigureAwait(false)).Select(View).ToList();
    }

    public Task<CredentialView> SuspendAsync(Guid id, int? expectedVersion, CancellationToken ct) =>
        ModifyAsync(id, expectedVersion, c => c.Suspend(), ct);

    public Task<CredentialView> ReinstateAsync(Guid id, int? expectedVersion, CancellationToken ct) =>
        ModifyAsync(id, expectedVersion, c => c.Reinstate(), ct);

    public Task<CredentialView> ReportLostAsync(Guid id, int? expectedVersion, CancellationToken ct) =>
        ModifyAsync(id, expectedVersion, c => c.ReportLost(), ct);

    public Task<CredentialView> RevokeAsync(Guid id, int? expectedVersion, CancellationToken ct) =>
        ModifyAsync(id, expectedVersion, c => c.Revoke(), ct);

    public Task<CredentialView> ChangeExpiryAsync(Guid id, ChangeCredentialExpiryRequest request, int? expectedVersion, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        return ModifyAsync(id, expectedVersion, c => c.ChangeExpiry(request.ExpiresAt), ct);
    }

    private CredentialView View(Credential c) => CredentialView.From(c, credentials.VersionOf(c));

    private async Task<CredentialView> ModifyAsync(Guid id, int? expectedVersion, Action<Credential> change, CancellationToken ct) =>
        View(await credentials.ModifyAsync(unitOfWork, id, Resource, expectedVersion, change, ct).ConfigureAwait(false));
}
