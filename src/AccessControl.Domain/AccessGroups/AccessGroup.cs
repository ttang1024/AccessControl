using AccessControl.Domain.Common;

namespace AccessControl.Domain.AccessGroups;

/// <summary>
/// The unit of permission: members of the group may open the group's doors while the
/// group's schedule is active. A cardholder's effective access is the union of their groups.
/// A <see cref="IsRestricted"/> group guards sensitive doors: only administrators may add members to it.
/// </summary>
public sealed class AccessGroup
{
    private readonly HashSet<Guid> _doorIds;

    private AccessGroup(Guid id, string name, Guid scheduleId, bool isRestricted, IEnumerable<Guid> doorIds)
    {
        Id = Guard.NotEmpty(id, "accessGroup.id");
        Name = name;
        ScheduleId = Guard.NotEmpty(scheduleId, "scheduleId");
        IsRestricted = isRestricted;
        _doorIds = new HashSet<Guid>(doorIds);
    }

    public Guid Id { get; }

    public string Name { get; private set; }

    public Guid ScheduleId { get; private set; }

    /// <summary>Only administrators may add members (segregation of duties for sensitive doors).</summary>
    public bool IsRestricted { get; private set; }

    public IReadOnlyCollection<Guid> DoorIds => _doorIds;

    public static AccessGroup Create(Guid id, string? name, Guid scheduleId, bool isRestricted = false) =>
        new(id, Guard.Name(name, "name"), scheduleId, isRestricted, []);

    /// <summary>Rebuilds an access group from persisted state. Not for creating new groups.</summary>
    public static AccessGroup Rehydrate(Guid id, string name, Guid scheduleId, bool isRestricted, IEnumerable<Guid> doorIds) =>
        new(id, name, scheduleId, isRestricted, doorIds);

    public void Rename(string? name) => Name = Guard.Name(name, "name");

    public void SetRestricted(bool isRestricted) => IsRestricted = isRestricted;

    public void ChangeSchedule(Guid scheduleId) => ScheduleId = Guard.NotEmpty(scheduleId, "scheduleId");

    public void AddDoor(Guid doorId) => _doorIds.Add(Guard.NotEmpty(doorId, "doorId"));

    public void RemoveDoor(Guid doorId) => _doorIds.Remove(doorId);

    public bool Covers(Guid doorId) => _doorIds.Contains(doorId);
}
