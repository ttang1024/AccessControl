using AccessControl.Application.Abstractions;
using AccessControl.Application.Errors;
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
    IReadOnlyList<Guid> AccessGroupIds,
    int Version) : IVersioned
{
    public static CardholderView From(Cardholder c, int version) =>
        new(c.Id, c.FirstName, c.LastName, c.EmployeeNumber, c.IsEnabled, c.ValidFrom, c.ValidUntil,
            c.AccessGroupIds.Order().ToList(), version);
}

public sealed class CardholderService(
    ICardholderRepository cardholders,
    IAccessGroupRepository accessGroups,
    IUnitOfWork unitOfWork,
    IActorContext actor)
{
    private const string Resource = ResourceNames.Cardholder;

    public async Task<CardholderView> CreateAsync(CardholderRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var cardholder = Cardholder.Create(Guid.NewGuid(), request.FirstName, request.LastName, request.EmployeeNumber);
        cardholder.SetValidityPeriod(request.ValidFrom, request.ValidUntil);

        cardholders.Add(cardholder);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return View(cardholder);
    }

    public async Task<CardholderView> GetAsync(Guid id, CancellationToken ct) =>
        View(await cardholders.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false));

    public async Task<PagedResult<CardholderView>> SearchAsync(
        string? text, Guid? accessGroupId, PageRequest page, CancellationToken ct) =>
        (await cardholders.SearchAsync(text, accessGroupId, page, ct).ConfigureAwait(false)).Map(View);

    public Task<CardholderView> UpdateAsync(Guid id, CardholderRequest request, int? expectedVersion, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        return ModifyAsync(id, expectedVersion, c =>
        {
            c.UpdateDetails(request.FirstName, request.LastName, request.EmployeeNumber);
            c.SetValidityPeriod(request.ValidFrom, request.ValidUntil);
        }, ct);
    }

    public Task<CardholderView> EnableAsync(Guid id, int? expectedVersion, CancellationToken ct) =>
        ModifyAsync(id, expectedVersion, c => c.Enable(), ct);

    public Task<CardholderView> DisableAsync(Guid id, int? expectedVersion, CancellationToken ct) =>
        ModifyAsync(id, expectedVersion, c => c.Disable(), ct);

    /// <summary>
    /// Adds the cardholder to a group. Restricted groups (sensitive doors) only accept members added by an
    /// administrator, so an operator cannot grant anyone, themselves included, access to those doors.
    /// </summary>
    public async Task<CardholderView> JoinAccessGroupAsync(Guid id, Guid accessGroupId, int? expectedVersion, CancellationToken ct)
    {
        var cardholder = await cardholders.GetForChangeAsync(id, Resource, expectedVersion, ct).ConfigureAwait(false);
        var group = await accessGroups.GetRequiredAsync(accessGroupId, ResourceNames.AccessGroup, ct).ConfigureAwait(false);
        if (group.IsRestricted && !actor.CanGrantRestrictedAccess && !cardholder.AccessGroupIds.Contains(group.Id))
        {
            throw new ForbiddenException(
                "accessgroup.restricted", $"Access group '{group.Name}' is restricted: only an administrator can add members.");
        }

        cardholder.JoinAccessGroup(accessGroupId);
        cardholders.Update(cardholder);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return View(cardholder);
    }

    /// <summary>Removing access is always allowed for enrolment staff, restricted group or not.</summary>
    public Task<CardholderView> LeaveAccessGroupAsync(Guid id, Guid accessGroupId, int? expectedVersion, CancellationToken ct) =>
        ModifyAsync(id, expectedVersion, c => c.LeaveAccessGroup(accessGroupId), ct);

    private CardholderView View(Cardholder c) => CardholderView.From(c, cardholders.VersionOf(c));

    private async Task<CardholderView> ModifyAsync(Guid id, int? expectedVersion, Action<Cardholder> change, CancellationToken ct) =>
        View(await cardholders.ModifyAsync(unitOfWork, id, Resource, expectedVersion, change, ct).ConfigureAwait(false));
}
