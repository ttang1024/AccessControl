using AccessControl.Domain.Common;
using AccessControl.Domain.Schedules;
using Xunit;

namespace AccessControl.Tests.Domain;

public sealed class ScheduleTests
{
    private static WeeklyTimeWindow Window(DayOfWeek day, string start, string end) =>
        WeeklyTimeWindow.Create(day, WeeklyTimeWindow.ParseTime(start, "start"), WeeklyTimeWindow.ParseTime(end, "end"));

    [Fact]
    public void Window_is_half_open()
    {
        var schedule = Schedule.Create(Guid.NewGuid(), "Office", "UTC", [Window(DayOfWeek.Monday, "08:00", "17:00")]);
        var monday = new DateTimeOffset(2026, 10, 5, 0, 0, 0, TimeSpan.Zero);

        Assert.False(schedule.IsActiveAt(monday.AddHours(8).AddTicks(-1)));
        Assert.True(schedule.IsActiveAt(monday.AddHours(8)));
        Assert.True(schedule.IsActiveAt(monday.AddHours(17).AddTicks(-1)));
        Assert.False(schedule.IsActiveAt(monday.AddHours(17)));
    }

    [Fact]
    public void End_of_day_24_00_covers_the_last_minute()
    {
        var schedule = Schedule.Create(Guid.NewGuid(), "Late", "UTC", [Window(DayOfWeek.Monday, "22:00", "24:00")]);
        var lastMoment = new DateTimeOffset(2026, 10, 5, 23, 59, 59, TimeSpan.Zero);

        Assert.True(schedule.IsActiveAt(lastMoment));
        Assert.False(schedule.IsActiveAt(lastMoment.AddSeconds(1))); // Tuesday 00:00
    }

    [Fact]
    public void Evaluates_in_schedule_time_zone_across_daylight_saving()
    {
        // New Zealand: NZST (UTC+12) until 2026-09-27 02:00, then NZDT (UTC+13).
        var schedule = Schedule.Create(
            Guid.NewGuid(), "Office", "Pacific/Auckland", [Window(DayOfWeek.Monday, "08:00", "09:00")]);

        // Monday 21 Sep 2026 08:30 NZST == Sunday 20:30 UTC.
        Assert.True(schedule.IsActiveAt(new DateTimeOffset(2026, 9, 20, 20, 30, 0, TimeSpan.Zero)));

        // Monday 5 Oct 2026 08:30 NZDT == Sunday 19:30 UTC; 20:30 UTC is 09:30 local, outside.
        Assert.True(schedule.IsActiveAt(new DateTimeOffset(2026, 10, 4, 19, 30, 0, TimeSpan.Zero)));
        Assert.False(schedule.IsActiveAt(new DateTimeOffset(2026, 10, 4, 20, 30, 0, TimeSpan.Zero)));
    }

    [Theory]
    [InlineData("09:00", "09:00")]
    [InlineData("10:00", "09:00")]
    public void Rejects_empty_or_inverted_windows(string start, string end)
    {
        var ex = Assert.Throws<DomainException>(() => Window(DayOfWeek.Monday, start, end));
        Assert.Equal("window.invalid_range", ex.Code);
    }

    [Theory]
    [InlineData("9:00")]
    [InlineData("24:01")]
    [InlineData("25:00")]
    [InlineData("noon")]
    public void Rejects_malformed_times(string value)
    {
        Assert.Throws<DomainException>(() => WeeklyTimeWindow.ParseTime(value, "start"));
    }

    [Fact]
    public void Rejects_unknown_time_zone()
    {
        var ex = Assert.Throws<DomainException>(() => Schedule.Create(Guid.NewGuid(), "x", "Mars/Olympus_Mons", []));
        Assert.Equal("timeZone.unknown", ex.Code);
    }

    [Fact]
    public void Empty_schedule_is_never_active()
    {
        var schedule = Schedule.Create(Guid.NewGuid(), "Never", "UTC", []);
        Assert.False(schedule.IsActiveAt(DateTimeOffset.UtcNow));
    }
}
