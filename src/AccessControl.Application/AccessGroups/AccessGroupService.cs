using AccessControl.Application.Abstractions;
using AccessControl.Application.Cardholders;
using AccessControl.Application.Errors;
using AccessControl.Domain.AccessGroups;

namespace AccessControl.Application.AccessGroups;

/// <param name="Restricted">Only administrators may add members (sensitive doors). Defaults to false.</param>
public sealed record AccessGroupRequest(string? Name, Guid ScheduleId, bool? Restricted = null);

public sealed record AccessGroupView(Guid Id, string Name, Guid ScheduleId, bool Restricted, IReadOnlyList<Guid> DoorIds, int Version) : IVersioned
{
    public static AccessGroupView From(AccessGroup g, int version) =>
        new(g.Id, g.Name, g.ScheduleId, g.IsRestricted, g.DoorIds.Order().ToList(), version);
}

/// <summary>
/// Access groups. References (the schedule, doors) are checked by the store at commit, which reports a missing one
/// as 404 (<c>schedule.not_found</c>, <c>door.not_found</c>).
/// </summary>
public sealed class AccessGroupService(
    IAccessGroupRepository accessGroups,
    ICardholderRepository cardholders,
    IUnitOfWork unitOfWork)
{
    private const string Resource = ResourceNames.AccessGroup;

    public async Task<AccessGroupView> CreateAsync(AccessGroupRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var group = AccessGroup.Create(Guid.NewGuid(), request.Name, request.ScheduleId, request.Restricted ?? false);
        accessGroups.Add(group);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return View(group);
    }

    public async Task<AccessGroupView> GetAsync(Guid id, CancellationToken ct) =>
        View(await accessGroups.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false));

    public async Task<PagedResult<AccessGroupView>> SearchAsync(string? text, PageRequest page, CancellationToken ct) =>
        (await accessGroups.SearchAsync(text, page, ct).ConfigureAwait(false)).Map(View);

    public async Task<PagedResult<CardholderView>> ListMembersAsync(Guid id, PageRequest page, CancellationToken ct)
    {
        await accessGroups.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false);
        return (await cardholders.SearchAsync(null, id, page, ct).ConfigureAwait(false))
            .Map(c => CardholderView.From(c, cardholders.VersionOf(c)));
    }

    public Task<AccessGroupView> UpdateAsync(Guid id, AccessGroupRequest request, int? expectedVersion, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        return ModifyAsync(id, expectedVersion, g =>
        {
            g.Rename(request.Name);
            g.ChangeSchedule(request.ScheduleId);
            g.SetRestricted(request.Restricted ?? false);
        }, ct);
    }

    public Task<AccessGroupView> AddDoorAsync(Guid id, Guid doorId, int? expectedVersion, CancellationToken ct) =>
        ModifyAsync(id, expectedVersion, g => g.AddDoor(doorId), ct);

    public Task<AccessGroupView> RemoveDoorAsync(Guid id, Guid doorId, int? expectedVersion, CancellationToken ct) =>
        ModifyAsync(id, expectedVersion, g => g.RemoveDoor(doorId), ct);

    /// <summary>Deletes the group and removes every member from it, in one atomic commit.</summary>
    public async Task DeleteAsync(Guid id, int? expectedVersion, CancellationToken ct)
    {
        var group = await accessGroups.GetForChangeAsync(id, Resource, expectedVersion, ct).ConfigureAwait(false);
        foreach (var member in await cardholders.ListByAccessGroupAsync(id, ct).ConfigureAwait(false))
        {
            member.LeaveAccessGroup(id);
            cardholders.Update(member);
        }

        accessGroups.Remove(group);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
    }

    private AccessGroupView View(AccessGroup g) => AccessGroupView.From(g, accessGroups.VersionOf(g));

    private async Task<AccessGroupView> ModifyAsync(Guid id, int? expectedVersion, Action<AccessGroup> change, CancellationToken ct) =>
        View(await accessGroups.ModifyAsync(unitOfWork, id, Resource, expectedVersion, change, ct).ConfigureAwait(false));
}
