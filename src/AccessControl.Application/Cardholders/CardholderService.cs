using AccessControl.Application.Abstractions;
using AccessControl.Domain.Cardholders;

namespace AccessControl.Application.Cardholders;

public sealed record CardholderRequest(
    string? FirstName,
    string? LastName,
    string? EmployeeNumber,
    DateTimeOffset? ValidFrom,
    DateTimeOffset? ValidUntil);

public sealed record CardholderView(
    Guid Id,
    string FirstName,
    string LastName,
    string? EmployeeNumber,
    bool IsEnabled,
    DateTimeOffset? ValidFrom,
    DateTimeOffset? ValidUntil,
    IReadOnlyList<Guid> AccessGroupIds)
{
    public static CardholderView From(Cardholder c) =>
        new(c.Id, c.FirstName, c.LastName, c.EmployeeNumber, c.IsEnabled, c.ValidFrom, c.ValidUntil,
            c.AccessGroupIds.Order().ToList());
}

public sealed class CardholderService(
    ICardholderRepository cardholders,
    IAccessGroupRepository accessGroups,
    IUnitOfWork unitOfWork)
{
    private const string Resource = "Cardholder";

    public async Task<CardholderView> CreateAsync(CardholderRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var cardholder = Cardholder.Create(Guid.NewGuid(), request.FirstName, request.LastName, request.EmployeeNumber);
        cardholder.SetValidityPeriod(request.ValidFrom, request.ValidUntil);

        cardholders.Add(cardholder);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return CardholderView.From(cardholder);
    }

    public async Task<CardholderView> GetAsync(Guid id, CancellationToken ct) =>
        CardholderView.From(await cardholders.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false));

    public async Task<PagedResult<CardholderView>> SearchAsync(string? text, PageRequest page, CancellationToken ct) =>
        (await cardholders.SearchAsync(text, page, ct).ConfigureAwait(false)).Map(CardholderView.From);

    public Task<CardholderView> UpdateAsync(Guid id, CardholderRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        return ModifyAsync(id, c =>
        {
            c.UpdateDetails(request.FirstName, request.LastName, request.EmployeeNumber);
            c.SetValidityPeriod(request.ValidFrom, request.ValidUntil);
        }, ct);
    }

    public Task<CardholderView> EnableAsync(Guid id, CancellationToken ct) => ModifyAsync(id, c => c.Enable(), ct);

    public Task<CardholderView> DisableAsync(Guid id, CancellationToken ct) => ModifyAsync(id, c => c.Disable(), ct);

    public async Task<CardholderView> JoinAccessGroupAsync(Guid id, Guid accessGroupId, CancellationToken ct)
    {
        var cardholder = await cardholders.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false);
        await accessGroups.GetRequiredAsync(accessGroupId, "AccessGroup", ct).ConfigureAwait(false);
        return await SaveIfChangedAsync(cardholder, cardholder.JoinAccessGroup(accessGroupId), ct).ConfigureAwait(false);
    }

    public async Task<CardholderView> LeaveAccessGroupAsync(Guid id, Guid accessGroupId, CancellationToken ct)
    {
        var cardholder = await cardholders.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false);
        return await SaveIfChangedAsync(cardholder, cardholder.LeaveAccessGroup(accessGroupId), ct).ConfigureAwait(false);
    }

    private async Task<CardholderView> ModifyAsync(Guid id, Action<Cardholder> change, CancellationToken ct)
    {
        var cardholder = await cardholders.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false);
        change(cardholder);
        return await SaveIfChangedAsync(cardholder, changed: true, ct).ConfigureAwait(false);
    }

    /// <summary>Commits only when the command changed something, so no-op requests leave no change-trail entry.</summary>
    private async Task<CardholderView> SaveIfChangedAsync(Cardholder cardholder, bool changed, CancellationToken ct)
    {
        if (changed)
        {
            cardholders.Update(cardholder);
            await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        }

        return CardholderView.From(cardholder);
    }
}
