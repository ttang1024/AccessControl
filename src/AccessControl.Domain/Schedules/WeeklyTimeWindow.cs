using System.Globalization;
using AccessControl.Domain.Common;

namespace AccessControl.Domain.Schedules;

/// <summary>
/// A half-open interval <c>[Start, End)</c> of local wall-clock time on one day of the week.
/// <c>End</c> may be exactly 24:00 to cover the rest of the day. Overnight shifts are expressed
/// as two windows (e.g. Mon 22:00–24:00 and Tue 00:00–06:00).
/// </summary>
public sealed record WeeklyTimeWindow
{
    private static readonly TimeSpan EndOfDay = TimeSpan.FromHours(24);

    private WeeklyTimeWindow(DayOfWeek day, TimeSpan start, TimeSpan end)
    {
        Day = day;
        Start = start;
        End = end;
    }

    public DayOfWeek Day { get; }

    public TimeSpan Start { get; }

    public TimeSpan End { get; }

    public static WeeklyTimeWindow Create(DayOfWeek day, TimeSpan start, TimeSpan end)
    {
        if (!Enum.IsDefined(day))
        {
            throw DomainException.Validation("window.invalid_day", $"'{day}' is not a day of the week.");
        }

        if (start < TimeSpan.Zero || end > EndOfDay || start >= end)
        {
            throw DomainException.Validation(
                "window.invalid_range",
                $"Window {Format(start)}-{Format(end)} is invalid: need 00:00 <= start < end <= 24:00.");
        }

        if (start.Ticks % TimeSpan.TicksPerMinute != 0 || end.Ticks % TimeSpan.TicksPerMinute != 0)
        {
            throw DomainException.Validation(
                "window.invalid_precision", "Window boundaries must be whole minutes.");
        }

        return new WeeklyTimeWindow(day, start, end);
    }

    /// <summary>Parses "HH:mm" where "24:00" is allowed as an end-of-day marker.</summary>
    public static TimeSpan ParseTime(string? value, string field)
    {
        var text = value?.Trim();
        if (text == "24:00")
        {
            return EndOfDay;
        }

        if (text is not null
            && TimeOnly.TryParseExact(text, "HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out var time))
        {
            return time.ToTimeSpan();
        }

        throw DomainException.Validation($"{field}.invalid", $"{field} must be in HH:mm format (00:00-24:00).");
    }

    public static string Format(TimeSpan time) =>
        time == EndOfDay ? "24:00" : time.ToString(@"hh\:mm", CultureInfo.InvariantCulture);

    public bool Contains(DayOfWeek day, TimeSpan timeOfDay) =>
        day == Day && timeOfDay >= Start && timeOfDay < End;
}
