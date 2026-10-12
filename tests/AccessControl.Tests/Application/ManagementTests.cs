using AccessControl.Application.Abstractions;
using AccessControl.Application.AccessGroups;
using AccessControl.Application.Audit;
using AccessControl.Application.Cardholders;
using AccessControl.Application.Doors;
using AccessControl.Application.Errors;
using AccessControl.Application.Schedules;
using AccessControl.Domain.Doors;
using AccessControl.Tests.Support;
using Xunit;

namespace AccessControl.Tests.Application;

public sealed class ManagementTests : IDisposable
{
    private readonly TestHost _host = new();

    public void Dispose() => _host.Dispose();

    [Fact]
    public async Task A_change_based_on_a_stale_version_is_refused()
    {
        var created = await Cardholders(s => s.CreateAsync(new CardholderRequest("Ada", "Lovelace", null, null, null), default));
        Assert.Equal(1, created.Version);

        // Two operators open version 1. The first saves a new end date...
        var until = _host.Clock.Now.AddDays(30);
        var first = await Cardholders(s => s.UpdateAsync(created.Id, new CardholderRequest("Ada", "Lovelace", null, null, until), 1, default));
        Assert.Equal(2, first.Version);

        // ...the second, still looking at version 1, fixes a typo: refused instead of silently clearing the end date.
        var ex = await Assert.ThrowsAsync<PreconditionFailedException>(() =>
            Cardholders(s => s.UpdateAsync(created.Id, new CardholderRequest("Ada", "King", null, null, null), 1, default)));
        Assert.Equal("precondition_failed", ex.Code);
        Assert.Equal(until, (await Cardholders(s => s.GetAsync(created.Id, default))).ValidUntil);
    }

    [Fact]
    public async Task A_command_that_changes_nothing_keeps_the_version()
    {
        var door = await Doors(s => s.CreateAsync(new DoorRequest("Front", null), default));
        var locked = await Doors(s => s.LockdownAsync(door.Id, door.Version, default));
        var again = await Doors(s => s.LockdownAsync(door.Id, locked.Version, default));

        Assert.Equal(2, locked.Version);
        Assert.Equal(2, again.Version);
    }

    [Fact]
    public async Task Only_administrators_can_add_members_to_a_restricted_group()
    {
        var schedule = await _host.Scope<ScheduleService, ScheduleView>(s => s.CreateAsync(new ScheduleRequest("Always", "UTC", []), default));
        var vault = await _host.Scope<AccessGroupService, AccessGroupView>(s =>
            s.CreateAsync(new AccessGroupRequest("Vault", schedule.Id, Restricted: true), default));
        var ada = await Cardholders(s => s.CreateAsync(new CardholderRequest("Ada", "Lovelace", null, null, null), default));

        _host.Actor.CanGrantRestrictedAccess = false;
        var ex = await Assert.ThrowsAsync<ForbiddenException>(() => Cardholders(s => s.JoinAccessGroupAsync(ada.Id, vault.Id, null, default)));
        Assert.Equal("accessgroup.restricted", ex.Code);

        _host.Actor.CanGrantRestrictedAccess = true;
        await Cardholders(s => s.JoinAccessGroupAsync(ada.Id, vault.Id, null, default));

        // Removing access is never restricted.
        _host.Actor.CanGrantRestrictedAccess = false;
        Assert.Empty((await Cardholders(s => s.LeaveAccessGroupAsync(ada.Id, vault.Id, null, default))).AccessGroupIds);
    }

    [Fact]
    public async Task The_whole_site_locks_down_in_one_commit()
    {
        for (var i = 0; i < 3; i++)
        {
            await Doors(s => s.CreateAsync(new DoorRequest($"Door {i}", null), default));
        }

        var result = await _host.Scope<DoorService, SiteModeResult>(s => s.LockdownSiteAsync(default));
        Assert.Equal(new SiteModeResult(3, 3, DoorMode.Lockdown), result);
        var doors = await Doors(s => s.SearchAsync(null, PageRequest.From(null, null), default));
        Assert.All(doors.Items, d => Assert.Equal(DoorMode.Lockdown, d.Mode));

        var changes = await _host.Scope<AuditService, PagedResult<ChangeAuditEntry>>(s =>
            s.QueryChangesAsync(new ChangeAuditFilter(EntityType: "doors"), PageRequest.From(null, null), default));
        Assert.Single(changes.Items.Where(c => c.Kind == ChangeKind.Updated).Select(c => c.CommitId).Distinct());

        Assert.Equal(new SiteModeResult(3, 3, DoorMode.Secure), await _host.Scope<DoorService, SiteModeResult>(s => s.ReleaseSiteAsync(default)));
    }

    [Fact]
    public async Task Lists_filter_by_text_and_group_and_page_in_the_repository()
    {
        await Doors(s => s.CreateAsync(new DoorRequest("Server room", "Level 2"), default));
        await Doors(s => s.CreateAsync(new DoorRequest("Front door", "Lobby"), default));
        var byLocation = await Doors(s => s.SearchAsync("lobby", PageRequest.From(null, null), default));
        Assert.Equal(["Front door"], byLocation.Items.Select(d => d.Name));

        var schedule = await _host.Scope<ScheduleService, ScheduleView>(s => s.CreateAsync(new ScheduleRequest("Always", "UTC", []), default));
        var staff = await _host.Scope<AccessGroupService, AccessGroupView>(s => s.CreateAsync(new AccessGroupRequest("Staff", schedule.Id), default));
        foreach (var name in new[] { "Carol", "Alice", "Bob" })
        {
            var person = await Cardholders(s => s.CreateAsync(new CardholderRequest(name, "Smith", null, null, null), default));
            if (name != "Bob")
            {
                await Cardholders(s => s.JoinAccessGroupAsync(person.Id, staff.Id, null, default));
            }
        }

        var members = await _host.Scope<AccessGroupService, PagedResult<CardholderView>>(s => s.ListMembersAsync(staff.Id, PageRequest.From(1, 1), default));
        Assert.Equal(2, members.Total);
        Assert.Equal(["Carol"], members.Items.Select(c => c.FirstName));
        Assert.All(members.Items, c => Assert.Equal(2, c.Version));
    }

    [Fact]
    public async Task Missing_references_are_reported_by_the_store_as_not_found()
    {
        var schedule = await _host.Scope<ScheduleService, ScheduleView>(s => s.CreateAsync(new ScheduleRequest("Always", "UTC", []), default));
        var group = await _host.Scope<AccessGroupService, AccessGroupView>(s => s.CreateAsync(new AccessGroupRequest("Staff", schedule.Id), default));

        var door = await Assert.ThrowsAsync<NotFoundException>(() =>
            _host.Scope<AccessGroupService, AccessGroupView>(s => s.AddDoorAsync(group.Id, Guid.NewGuid(), null, default)));
        Assert.Equal("door.not_found", door.Code);

        var missingSchedule = await Assert.ThrowsAsync<NotFoundException>(() =>
            _host.Scope<AccessGroupService, AccessGroupView>(s => s.CreateAsync(new AccessGroupRequest("Ghost", Guid.NewGuid()), default)));
        Assert.Equal("schedule.not_found", missingSchedule.Code);
    }

    private Task<T> Cardholders<T>(Func<CardholderService, Task<T>> action) => _host.Scope(action);

    private Task<T> Doors<T>(Func<DoorService, Task<T>> action) => _host.Scope(action);
}
