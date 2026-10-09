using AccessControl.Application.Abstractions;
using AccessControl.Application.Errors;
using AccessControl.Domain.Schedules;

namespace AccessControl.Application.Schedules;

/// <param name="Day">Day of week, e.g. "Monday".</param>
/// <param name="Start">Local start time, "HH:mm", inclusive.</param>
/// <param name="End">Local end time, "HH:mm", exclusive; "24:00" means end of day.</param>
public sealed record TimeWindowDto(DayOfWeek Day, string Start, string End);

public sealed record ScheduleRequest(string? Name, string? TimeZone, IReadOnlyList<TimeWindowDto>? Windows);

public sealed record ScheduleView(Guid Id, string Name, string TimeZone, IReadOnlyList<TimeWindowDto> Windows)
{
    public static ScheduleView From(Schedule s) =>
        new(s.Id, s.Name, s.TimeZone.Id,
            s.Windows
                .Select(w => new TimeWindowDto(w.Day, WeeklyTimeWindow.Format(w.Start), WeeklyTimeWindow.Format(w.End)))
                .ToList());
}

public sealed class ScheduleService(
    IScheduleRepository schedules,
    IAccessGroupRepository accessGroups,
    IUnitOfWork unitOfWork)
{
    private const string Resource = ResourceNames.Schedule;
    private const int MaxWindows = 200;

    public async Task<ScheduleView> CreateAsync(ScheduleRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var schedule = Schedule.Create(Guid.NewGuid(), request.Name, request.TimeZone, ToWindows(request.Windows));
        schedules.Add(schedule);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return ScheduleView.From(schedule);
    }

    public async Task<ScheduleView> GetAsync(Guid id, CancellationToken ct) =>
        ScheduleView.From(await schedules.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false));

    public async Task<PagedResult<ScheduleView>> ListAsync(PageRequest page, CancellationToken ct) =>
        PagedResult.Create(
            (await schedules.ListAsync(ct).ConfigureAwait(false))
                .OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
                .ThenBy(s => s.Id)
                .Select(ScheduleView.From),
            page);

    /// <summary>Replaces the schedule's name, time zone and windows. Takes effect on the next badge read.</summary>
    public async Task<ScheduleView> UpdateAsync(Guid id, ScheduleRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var schedule = await schedules.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false);
        schedule.Rename(request.Name);
        schedule.Redefine(request.TimeZone, ToWindows(request.Windows));
        schedules.Update(schedule);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return ScheduleView.From(schedule);
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct)
    {
        var schedule = await schedules.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false);
        var groups = await accessGroups.ListByScheduleAsync(id, ct).ConfigureAwait(false);
        if (groups.Count > 0)
        {
            throw ConflictException.InUseByGroups(Resource, groups.Select(g => g.Name).ToList());
        }

        schedules.Remove(schedule);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
    }

    private static List<WeeklyTimeWindow> ToWindows(IReadOnlyList<TimeWindowDto>? windows)
    {
        if (windows is null)
        {
            throw new RequestValidationException("windows.required", "windows is required (may be empty).");
        }

        if (windows.Count > MaxWindows)
        {
            throw new RequestValidationException("windows.too_many", $"A schedule may have at most {MaxWindows} windows.");
        }

        return windows
            .Select(w => w is null
                ? throw new RequestValidationException("windows.invalid", "windows must not contain null entries.")
                : WeeklyTimeWindow.Create(
                    w.Day,
                    WeeklyTimeWindow.ParseTime(w.Start, "start"),
                    WeeklyTimeWindow.ParseTime(w.End, "end")))
            .ToList();
    }
}
