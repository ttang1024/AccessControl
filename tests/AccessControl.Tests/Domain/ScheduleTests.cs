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

    [Fact]
    public void Local_times_skipped_by_spring_forward_never_match_and_windows_shrink()
    {
        // 2026-09-27 02:00 NZST jumps to 03:00 NZDT at 14:00 UTC: local 02:00-03:00 does not exist that night.
        var gap = Schedule.Create(Guid.NewGuid(), "Gap", "Pacific/Auckland", [Window(DayOfWeek.Sunday, "02:00", "03:00")]);
        for (var utc = new DateTimeOffset(2026, 9, 26, 13, 0, 0, TimeSpan.Zero); utc < new DateTimeOffset(2026, 9, 26, 16, 0, 0, TimeSpan.Zero); utc = utc.AddMinutes(1))
        {
            Assert.False(gap.IsActiveAt(utc), $"active at {utc:u}");
        }

        // A 01:00-04:00 window covers only two real hours that night.
        var night = Schedule.Create(Guid.NewGuid(), "Night", "Pacific/Auckland", [Window(DayOfWeek.Sunday, "01:00", "04:00")]);
        Assert.False(night.IsActiveAt(new DateTimeOffset(2026, 9, 26, 12, 59, 0, TimeSpan.Zero)));
        Assert.True(night.IsActiveAt(new DateTimeOffset(2026, 9, 26, 13, 0, 0, TimeSpan.Zero)));  // 01:00 NZST
        Assert.True(night.IsActiveAt(new DateTimeOffset(2026, 9, 26, 14, 59, 0, TimeSpan.Zero))); // 03:59 NZDT
        Assert.False(night.IsActiveAt(new DateTimeOffset(2026, 9, 26, 15, 0, 0, TimeSpan.Zero))); // 04:00 NZDT
    }

    [Fact]
    public void Local_times_repeated_by_fall_back_match_both_times()
    {
        // 2027-04-04 03:00 NZDT falls back to 02:00 NZST at 14:00 UTC: local 02:00-03:00 happens twice.
        var schedule = Schedule.Create(Guid.NewGuid(), "Twice", "Pacific/Auckland", [Window(DayOfWeek.Sunday, "02:00", "03:00")]);

        Assert.False(schedule.IsActiveAt(new DateTimeOffset(2027, 4, 3, 12, 59, 0, TimeSpan.Zero)));
        Assert.True(schedule.IsActiveAt(new DateTimeOffset(2027, 4, 3, 13, 30, 0, TimeSpan.Zero))); // 02:30 NZDT
        Assert.True(schedule.IsActiveAt(new DateTimeOffset(2027, 4, 3, 14, 30, 0, TimeSpan.Zero))); // 02:30 NZST
        Assert.False(schedule.IsActiveAt(new DateTimeOffset(2027, 4, 3, 15, 0, 0, TimeSpan.Zero)));  // 03:00 NZST
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
