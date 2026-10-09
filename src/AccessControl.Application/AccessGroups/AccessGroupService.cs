using AccessControl.Application.Abstractions;
using AccessControl.Application.Cardholders;
using AccessControl.Application.Errors;
using AccessControl.Domain.AccessGroups;

namespace AccessControl.Application.AccessGroups;

public sealed record AccessGroupRequest(string? Name, Guid ScheduleId);

public sealed record AccessGroupView(Guid Id, string Name, Guid ScheduleId, IReadOnlyList<Guid> DoorIds)
{
    public static AccessGroupView From(AccessGroup g) => new(g.Id, g.Name, g.ScheduleId, g.DoorIds.Order().ToList());
}

public sealed class AccessGroupService(
    IAccessGroupRepository accessGroups,
    IScheduleRepository schedules,
    IDoorRepository doors,
    ICardholderRepository cardholders,
    IUnitOfWork unitOfWork)
{
    private const string Resource = ResourceNames.AccessGroup;

    public async Task<AccessGroupView> CreateAsync(AccessGroupRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var group = AccessGroup.Create(Guid.NewGuid(), request.Name, request.ScheduleId);
        await schedules.GetRequiredAsync(request.ScheduleId, ResourceNames.Schedule, ct).ConfigureAwait(false);

        accessGroups.Add(group);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return AccessGroupView.From(group);
    }

    public async Task<AccessGroupView> GetAsync(Guid id, CancellationToken ct) =>
        AccessGroupView.From(await accessGroups.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false));

    public async Task<PagedResult<AccessGroupView>> ListAsync(PageRequest page, CancellationToken ct) =>
        PagedResult.Create(
            (await accessGroups.ListAsync(ct).ConfigureAwait(false))
                .OrderBy(g => g.Name, StringComparer.OrdinalIgnoreCase)
                .ThenBy(g => g.Id)
                .Select(AccessGroupView.From),
            page);

    public async Task<PagedResult<CardholderView>> ListMembersAsync(Guid id, PageRequest page, CancellationToken ct)
    {
        await accessGroups.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false);
        return PagedResult.Create(
            (await cardholders.ListByAccessGroupAsync(id, ct).ConfigureAwait(false))
                .OrderBy(c => c.LastName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(c => c.FirstName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(c => c.Id)
                .Select(CardholderView.From),
            page);
    }

    public async Task<AccessGroupView> UpdateAsync(Guid id, AccessGroupRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var group = await accessGroups.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false);
        group.Rename(request.Name);
        group.ChangeSchedule(request.ScheduleId);
        await schedules.GetRequiredAsync(request.ScheduleId, ResourceNames.Schedule, ct).ConfigureAwait(false);

        accessGroups.Update(group);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return AccessGroupView.From(group);
    }

    public async Task<AccessGroupView> AddDoorAsync(Guid id, Guid doorId, CancellationToken ct)
    {
        var group = await accessGroups.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false);
        await doors.GetRequiredAsync(doorId, ResourceNames.Door, ct).ConfigureAwait(false);
        group.AddDoor(doorId);
        accessGroups.Update(group);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return AccessGroupView.From(group);
    }

    public async Task<AccessGroupView> RemoveDoorAsync(Guid id, Guid doorId, CancellationToken ct) =>
        AccessGroupView.From(await accessGroups
            .ModifyAsync(unitOfWork, id, Resource, g => g.RemoveDoor(doorId), ct)
            .ConfigureAwait(false));

    /// <summary>Deletes the group and removes every member from it, in one atomic commit.</summary>
    public async Task DeleteAsync(Guid id, CancellationToken ct)
    {
        var group = await accessGroups.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false);
        foreach (var member in await cardholders.ListByAccessGroupAsync(id, ct).ConfigureAwait(false))
        {
            member.LeaveAccessGroup(id);
            cardholders.Update(member);
        }

        accessGroups.Remove(group);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
    }
}
