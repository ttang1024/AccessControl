using AccessControl.Application.Abstractions;
using AccessControl.Application.Errors;
using AccessControl.Domain.Doors;
using Microsoft.Extensions.Logging;

namespace AccessControl.Application.Doors;

public sealed record DoorRequest(string? Name, string? Location);

public sealed record DoorView(Guid Id, string Name, string? Location, DoorMode Mode)
{
    public static DoorView From(Door d) => new(d.Id, d.Name, d.Location, d.Mode);
}

public sealed partial class DoorService(
    IDoorRepository doors,
    IAccessGroupRepository accessGroups,
    IUnitOfWork unitOfWork,
    ILogger<DoorService> logger)
{
    private const string Resource = "Door";

    public async Task<DoorView> CreateAsync(DoorRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var door = Door.Create(Guid.NewGuid(), request.Name, request.Location);
        doors.Add(door);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return DoorView.From(door);
    }

    public async Task<DoorView> GetAsync(Guid id, CancellationToken ct) =>
        DoorView.From(await doors.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false));

    public async Task<IReadOnlyList<DoorView>> ListAsync(CancellationToken ct) =>
        (await doors.ListAsync(ct).ConfigureAwait(false))
            .OrderBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
            .Select(DoorView.From)
            .ToList();

    public Task<DoorView> UpdateAsync(Guid id, DoorRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        return ModifyAsync(id, d => d.UpdateDetails(request.Name, request.Location), ct);
    }

    public async Task<DoorView> LockdownAsync(Guid id, CancellationToken ct)
    {
        var view = await ModifyAsync(id, d => d.Lockdown(), ct).ConfigureAwait(false);
        Log.LockdownChanged(logger, view.Id, view.Name, "placed in");
        return view;
    }

    public async Task<DoorView> ReleaseLockdownAsync(Guid id, CancellationToken ct)
    {
        var view = await ModifyAsync(id, d => d.ReleaseLockdown(), ct).ConfigureAwait(false);
        Log.LockdownChanged(logger, view.Id, view.Name, "released from");
        return view;
    }

    /// <summary>Deletes a door that no access group references. Its audit history is kept.</summary>
    public async Task DeleteAsync(Guid id, CancellationToken ct)
    {
        var door = await doors.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false);
        var groups = await accessGroups.ListByDoorAsync(id, ct).ConfigureAwait(false);
        if (groups.Count > 0)
        {
            throw ConflictException.InUseByGroups(Resource, groups.Select(g => g.Name).ToList());
        }

        doors.Remove(door);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
    }

    private async Task<DoorView> ModifyAsync(Guid id, Action<Door> change, CancellationToken ct)
    {
        var door = await doors.GetRequiredAsync(id, Resource, ct).ConfigureAwait(false);
        change(door);
        doors.Update(door);
        await unitOfWork.CommitAsync(ct).ConfigureAwait(false);
        return DoorView.From(door);
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 2000, Level = LogLevel.Warning, Message = "Door {DoorId} ({DoorName}) {Change} lockdown")]
        public static partial void LockdownChanged(ILogger logger, Guid doorId, string doorName, string change);
    }
}
