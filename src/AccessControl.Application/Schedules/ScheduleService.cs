using AccessControl.Application.Abstractions;
using AccessControl.Application.Errors;
using AccessControl.Domain.Schedules;

namespace AccessControl.Application.Schedules;

/// <param name="Day">Day of week, e.g. "Monday".</param>
/// <param name="Start">Local start time, "HH:mm", inclusive.</param>
/// <param name="End">Local end time, "HH:mm", exclusive; "24:00" means end of day.</param>
public sealed record TimeWindowDto(DayOfWeek Day, string Start, string End);

public sealed record ScheduleRequest(string? Name, string? TimeZone, IReadOnlyList<TimeWindowDto>? Windows);

public sealed record ScheduleView(Guid Id, string Name, string TimeZone, IReadOnlyList<TimeWindowDto> Windows, int Version) : IVersioned
{
    public static ScheduleView From(Schedule s, int version) =>
        new(s.Id, s.Name, s.TimeZone.Id,
            s.Windows
                .Select(w => new TimeWindowDto(w.Day, WeeklyTimeWindow.Format(w.Start), WeeklyTimeWindow.Format(w.End)))
                .ToList(),
            version);
}

public sealed class ScheduleService(IScheduleRepository schedules, IUnitOfWork unitOfWork)
{
    private const string Resource = ResourceNames.Schedule;
    private const int MaxWindows = 200;

    public async Task<ScheduleView> CreateAsync(ScheduleRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var schedule = Schedule.Create(Guid.NewGuid(), request.Name, request.TimeZone, ToWindows(request.Windows));
        schedules.Add(schedule);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return View(schedule);
    }

    public async Task<ScheduleView> GetAsync(Guid id, CancellationToken ct) =>
        View(await schedules.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false));

    public async Task<PagedResult<ScheduleView>> SearchAsync(string? text, PageRequest page, CancellationToken ct) =>
        (await schedules.SearchAsync(text, page, ct).ConfigureAwait(false)).Map(View);

    /// <summary>Replaces the schedule's name, time zone and windows. Takes effect on the next badge read.</summary>
    public async Task<ScheduleView> UpdateAsync(Guid id, ScheduleRequest request, int? expectedVersion, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var windows = ToWindows(request.Windows);
        return View(await schedules.ModifyAsync(unitOfWork, id, Resource, expectedVersion, s =>
        {
            s.Rename(request.Name);
            s.Redefine(request.TimeZone, windows);
        }, ct).ConfigureAwait(false));
    }

    /// <summary>Deletes a schedule. Refused (<c>schedule.in_use</c>) by the store while an access group uses it.</summary>
    public async Task DeleteAsync(Guid id, int? expectedVersion, CancellationToken ct)
    {
        schedules.Remove(await schedules.GetForChangeAsync(id, Resource, expectedVersion, ct).ConfigureAwait(false));
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
    }

    private ScheduleView View(Schedule s) => ScheduleView.From(s, schedules.VersionOf(s));

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
