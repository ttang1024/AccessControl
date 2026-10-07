using AccessControl.Domain.Common;

namespace AccessControl.Domain.Schedules;

/// <summary>
/// A recurring weekly pattern of times when access is allowed, evaluated in the site's time zone
/// so that daylight-saving changes are handled by the platform time-zone database.
/// </summary>
public sealed class Schedule
{
    private List<WeeklyTimeWindow> _windows;

    private Schedule(Guid id, string name, TimeZoneInfo timeZone, IEnumerable<WeeklyTimeWindow> windows)
    {
        Id = Guard.NotEmpty(id, "schedule.id");
        Name = name;
        TimeZone = timeZone;
        _windows = Normalize(windows);
    }

    public Guid Id { get; }

    public string Name { get; private set; }

    public TimeZoneInfo TimeZone { get; private set; }

    public IReadOnlyList<WeeklyTimeWindow> Windows => _windows;

    public static Schedule Create(Guid id, string? name, string? timeZoneId, IEnumerable<WeeklyTimeWindow> windows) =>
        new(id, Guard.Name(name, "name"), ResolveTimeZone(timeZoneId), windows);

    /// <summary>Rebuilds a schedule from persisted state. Not for creating new schedules.</summary>
    public static Schedule Rehydrate(Guid id, string name, string timeZoneId, IEnumerable<WeeklyTimeWindow> windows) =>
        new(id, name, ResolveTimeZone(timeZoneId), windows);

    public static TimeZoneInfo ResolveTimeZone(string? timeZoneId)
    {
        if (string.IsNullOrWhiteSpace(timeZoneId))
        {
            throw DomainException.Validation("timeZone.required", "timeZone is required (IANA id, e.g. Pacific/Auckland).");
        }

        try
        {
            return TimeZoneInfo.FindSystemTimeZoneById(timeZoneId.Trim());
        }
        catch (Exception ex) when (ex is TimeZoneNotFoundException or InvalidTimeZoneException)
        {
            throw DomainException.Validation("timeZone.unknown", $"Unknown time zone '{timeZoneId}'.");
        }
    }

    public void Rename(string? name) => Name = Guard.Name(name, "name");

    public void Redefine(string? timeZoneId, IEnumerable<WeeklyTimeWindow> windows)
    {
        var timeZone = ResolveTimeZone(timeZoneId);
        _windows = Normalize(windows);
        TimeZone = timeZone;
    }

    /// <summary>True if <paramref name="instant"/> falls inside any window, in the schedule's local time.</summary>
    public bool IsActiveAt(DateTimeOffset instant)
    {
        var local = TimeZoneInfo.ConvertTime(instant, TimeZone);
        var day = local.DayOfWeek;
        var timeOfDay = local.TimeOfDay;
        return _windows.Exists(w => w.Contains(day, timeOfDay));
    }

    private static List<WeeklyTimeWindow> Normalize(IEnumerable<WeeklyTimeWindow> windows)
    {
        ArgumentNullException.ThrowIfNull(windows);
        return windows
            .Distinct()
            .OrderBy(w => w.Day)
            .ThenBy(w => w.Start)
            .ToList();
    }
}
