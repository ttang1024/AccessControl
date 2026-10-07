using AccessControl.Application.Abstractions;
using AccessControl.Application.Cardholders;
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
    private const string Resource = "AccessGroup";

    public async Task<AccessGroupView> CreateAsync(AccessGroupRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var group = AccessGroup.Create(Guid.NewGuid(), request.Name, request.ScheduleId);
        await schedules.GetRequiredAsync(request.ScheduleId, "Schedule", ct).ConfigureAwait(false);

        accessGroups.Add(group);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return AccessGroupView.From(group);
    }

    public async Task<AccessGroupView> GetAsync(Guid id, CancellationToken ct) =>
        AccessGroupView.From(await accessGroups.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false));

    public async Task<IReadOnlyList<AccessGroupView>> ListAsync(CancellationToken ct) =>
        (await accessGroups.ListAsync(ct).ConfigureAwait(false))
            .OrderBy(g => g.Name, StringComparer.OrdinalIgnoreCase)
            .Select(AccessGroupView.From)
            .ToList();

    public async Task<IReadOnlyList<CardholderView>> ListMembersAsync(Guid id, CancellationToken ct)
    {
        await accessGroups.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false);
        return (await cardholders.ListByAccessGroupAsync(id, ct).ConfigureAwait(false))
            .OrderBy(c => c.LastName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(c => c.FirstName, StringComparer.OrdinalIgnoreCase)
            .Select(CardholderView.From)
            .ToList();
    }

    public async Task<AccessGroupView> UpdateAsync(Guid id, AccessGroupRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var group = await accessGroups.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false);
        group.Rename(request.Name);
        group.ChangeSchedule(request.ScheduleId);
        await schedules.GetRequiredAsync(request.ScheduleId, "Schedule", ct).ConfigureAwait(false);

        accessGroups.Update(group);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return AccessGroupView.From(group);
    }

    public async Task<AccessGroupView> AddDoorAsync(Guid id, Guid doorId, CancellationToken ct)
    {
        var group = await accessGroups.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false);
        await doors.GetRequiredAsync(doorId, "Door", ct).ConfigureAwait(false);
        return await SaveIfChangedAsync(group, group.AddDoor(doorId), ct).ConfigureAwait(false);
    }

    public async Task<AccessGroupView> RemoveDoorAsync(Guid id, Guid doorId, CancellationToken ct)
    {
        var group = await accessGroups.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false);
        return await SaveIfChangedAsync(group, group.RemoveDoor(doorId), ct).ConfigureAwait(false);
    }

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

    /// <summary>Commits only when the command changed something, so no-op requests leave no change-trail entry.</summary>
    private async Task<AccessGroupView> SaveIfChangedAsync(AccessGroup group, bool changed, CancellationToken ct)
    {
        if (changed)
        {
            accessGroups.Update(group);
            await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        }

        return AccessGroupView.From(group);
    }
}
