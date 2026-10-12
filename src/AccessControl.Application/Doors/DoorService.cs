using AccessControl.Application.Abstractions;
using AccessControl.Application.Errors;
using AccessControl.Domain.Doors;
using Microsoft.Extensions.Logging;

namespace AccessControl.Application.Doors;

public sealed record DoorRequest(string? Name, string? Location);

public sealed record DoorView(Guid Id, string Name, string? Location, DoorMode Mode, int Version) : IVersioned
{
    public static DoorView From(Door d, int version) => new(d.Id, d.Name, d.Location, d.Mode, version);
}

/// <param name="Doors">Doors on the site.</param>
/// <param name="Changed">Doors whose mode this request changed (the others were already in the requested mode).</param>
public sealed record SiteModeResult(int Doors, int Changed, DoorMode Mode);

public sealed partial class DoorService(
    IDoorRepository doors,
    IUnitOfWork unitOfWork,
    ILogger<DoorService> logger)
{
    private const string Resource = ResourceNames.Door;

    public async Task<DoorView> CreateAsync(DoorRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var door = Door.Create(Guid.NewGuid(), request.Name, request.Location);
        doors.Add(door);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return View(door);
    }

    public async Task<DoorView> GetAsync(Guid id, CancellationToken ct) =>
        View(await doors.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false));

    public async Task<PagedResult<DoorView>> SearchAsync(string? text, PageRequest page, CancellationToken ct) =>
        (await doors.SearchAsync(text, page, ct).ConfigureAwait(false)).Map(View);

    public Task<DoorView> UpdateAsync(Guid id, DoorRequest request, int? expectedVersion, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        return ModifyAsync(id, expectedVersion, d => d.UpdateDetails(request.Name, request.Location), ct);
    }

    public async Task<DoorView> LockdownAsync(Guid id, int? expectedVersion, CancellationToken ct)
    {
        var view = await ModifyAsync(id, expectedVersion, d => d.Lockdown(), ct).ConfigureAwait(false);
        Log.LockdownChanged(logger, view.Id, view.Name, "placed in");
        return view;
    }

    public async Task<DoorView> ReleaseLockdownAsync(Guid id, int? expectedVersion, CancellationToken ct)
    {
        var view = await ModifyAsync(id, expectedVersion, d => d.ReleaseLockdown(), ct).ConfigureAwait(false);
        Log.LockdownChanged(logger, view.Id, view.Name, "released from");
        return view;
    }

    /// <summary>Puts every door into lockdown in one atomic commit: one call in an emergency, not one per door.</summary>
    public Task<SiteModeResult> LockdownSiteAsync(CancellationToken ct) => SetSiteModeAsync(DoorMode.Lockdown, ct);

    /// <summary>Releases every door from lockdown in one atomic commit.</summary>
    public Task<SiteModeResult> ReleaseSiteAsync(CancellationToken ct) => SetSiteModeAsync(DoorMode.Secure, ct);

    /// <summary>
    /// Deletes a door. Refused (<c>door.in_use</c>) by the store while an access group still includes it. Its audit
    /// history is kept.
    /// </summary>
    public async Task DeleteAsync(Guid id, int? expectedVersion, CancellationToken ct)
    {
        doors.Remove(await doors.GetForChangeAsync(id, Resource, expectedVersion, ct).ConfigureAwait(false));
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
    }

    private async Task<SiteModeResult> SetSiteModeAsync(DoorMode mode, CancellationToken ct)
    {
        var all = await doors.ListAllAsync(ct).ConfigureAwait(false);
        var changed = all.Where(d => d.Mode != mode).ToList();
        foreach (var door in changed)
        {
            if (mode == DoorMode.Lockdown)
            {
                door.Lockdown();
            }
            else
            {
                door.ReleaseLockdown();
            }

            doors.Update(door);
        }

        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        Log.SiteModeChanged(logger, mode, changed.Count, all.Count);
        return new SiteModeResult(all.Count, changed.Count, mode);
    }

    private DoorView View(Door d) => DoorView.From(d, doors.VersionOf(d));

    private async Task<DoorView> ModifyAsync(Guid id, int? expectedVersion, Action<Door> change, CancellationToken ct) =>
        View(await doors.ModifyAsync(unitOfWork, id, Resource, expectedVersion, change, ct).ConfigureAwait(false));

    private static partial class Log
    {
        [LoggerMessage(EventId = 2000, Level = LogLevel.Warning, Message = "Door {DoorId} ({DoorName}) {Change} lockdown")]
        public static partial void LockdownChanged(ILogger logger, Guid doorId, string doorName, string change);

        [LoggerMessage(EventId = 2001, Level = LogLevel.Warning, Message = "Site set to {Mode}: {Changed} of {Doors} doors changed")]
        public static partial void SiteModeChanged(ILogger logger, DoorMode mode, int changed, int doors);
    }
}
