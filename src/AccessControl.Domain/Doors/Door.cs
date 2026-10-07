using AccessControl.Domain.Common;

namespace AccessControl.Domain.Doors;

public enum DoorMode
{
    /// <summary>Access is decided per request by credentials, groups and schedules.</summary>
    Secure,

    /// <summary>Every badge request is denied, regardless of permissions.</summary>
    Lockdown,
}

/// <summary>A controlled entry point with a reader.</summary>
public sealed class Door
{
    private Door(Guid id, string name, string? location, DoorMode mode)
    {
        Id = Guard.NotEmpty(id, "door.id");
        Name = name;
        Location = location;
        Mode = mode;
    }

    public Guid Id { get; }

    public string Name { get; private set; }

    public string? Location { get; private set; }

    public DoorMode Mode { get; private set; }

    public static Door Create(Guid id, string? name, string? location) =>
        new(id, Guard.Name(name, "name"), Guard.Optional(location, "location", 200), DoorMode.Secure);

    /// <summary>Rebuilds a door from persisted state. Not for creating new doors.</summary>
    public static Door Rehydrate(Guid id, string name, string? location, DoorMode mode) =>
        new(id, name, location, mode);

    public void UpdateDetails(string? name, string? location)
    {
        Name = Guard.Name(name, "name");
        Location = Guard.Optional(location, "location", 200);
    }

    /// <summary>Idempotent: locking a locked-down door is not an error.</summary>
    public void Lockdown() => Mode = DoorMode.Lockdown;

    /// <summary>Idempotent: releasing a secure door is not an error.</summary>
    public void ReleaseLockdown() => Mode = DoorMode.Secure;
}
