using AccessControl.Domain.Common;

namespace AccessControl.Domain.AccessGroups;

/// <summary>
/// The unit of permission: members of the group may open the group's doors while the
/// group's schedule is active. A cardholder's effective access is the union of their groups.
/// </summary>
public sealed class AccessGroup
{
    private readonly HashSet<Guid> _doorIds;

    private AccessGroup(Guid id, string name, Guid scheduleId, IEnumerable<Guid> doorIds)
    {
        Id = Guard.NotEmpty(id, "accessGroup.id");
        Name = name;
        ScheduleId = Guard.NotEmpty(scheduleId, "scheduleId");
        _doorIds = new HashSet<Guid>(doorIds);
    }

    public Guid Id { get; }

    public string Name { get; private set; }

    public Guid ScheduleId { get; private set; }

    public IReadOnlyCollection<Guid> DoorIds => _doorIds;

    public static AccessGroup Create(Guid id, string? name, Guid scheduleId) =>
        new(id, Guard.Name(name, "name"), scheduleId, []);

    /// <summary>Rebuilds an access group from persisted state. Not for creating new groups.</summary>
    public static AccessGroup Rehydrate(Guid id, string name, Guid scheduleId, IEnumerable<Guid> doorIds) =>
        new(id, name, scheduleId, doorIds);

    public void Rename(string? name) => Name = Guard.Name(name, "name");

    public void ChangeSchedule(Guid scheduleId) => ScheduleId = Guard.NotEmpty(scheduleId, "scheduleId");

    /// <returns><c>false</c> if the door was already in the group.</returns>
    public bool AddDoor(Guid doorId) => _doorIds.Add(Guard.NotEmpty(doorId, "doorId"));

    /// <returns><c>false</c> if the door was not in the group.</returns>
    public bool RemoveDoor(Guid doorId) => _doorIds.Remove(doorId);

    public bool Covers(Guid doorId) => _doorIds.Contains(doorId);
}
