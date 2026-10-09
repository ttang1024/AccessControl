using AccessControl.Application.Abstractions;
using AccessControl.Application.AccessGroups;
using AccessControl.Application.Cardholders;
using AccessControl.Application.Doors;
using AccessControl.Application.Errors;
using AccessControl.Application.Schedules;
using AccessControl.Domain.AccessGroups;
using AccessControl.Domain.Doors;
using AccessControl.Infrastructure.Storage;
using AccessControl.Tests.Support;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AccessControl.Tests.Infrastructure;

public sealed class DocumentStoreTests : IDisposable
{
    private readonly TestHost _host = new();

    public void Dispose() => _host.Dispose();

    [Fact]
    public async Task Concurrent_update_of_the_same_aggregate_is_rejected()
    {
        var door = await _host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest("A", null), default));

        using var first = _host.CreateScope();
        using var second = _host.CreateScope();
        var repoA = first.ServiceProvider.GetRequiredService<IDoorRepository>();
        var repoB = second.ServiceProvider.GetRequiredService<IDoorRepository>();

        var a = (await repoA.GetAsync(door.Id, default))!;
        var b = (await repoB.GetAsync(door.Id, default))!;

        a.UpdateDetails("Renamed by A", null);
        repoA.Update(a);
        await first.ServiceProvider.GetRequiredService<IUnitOfWork>().CommitAsync(default);

        b.Lockdown();
        repoB.Update(b);
        var ex = await Assert.ThrowsAsync<ConflictException>(() =>
            second.ServiceProvider.GetRequiredService<IUnitOfWork>().CommitAsync(default));
        Assert.Equal("concurrency_conflict", ex.Code);

        // The losing write left no trace.
        var current = await _host.Scope<DoorService, DoorView>(s => s.GetAsync(door.Id, default));
        Assert.Equal("Renamed by A", current.Name);
        Assert.Equal(DoorMode.Secure, current.Mode);
    }

    [Fact]
    public async Task Uncommitted_changes_are_not_visible()
    {
        var door = await _host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest("A", null), default));

        using (var scope = _host.CreateScope())
        {
            var repo = scope.ServiceProvider.GetRequiredService<IDoorRepository>();
            var loaded = (await repo.GetAsync(door.Id, default))!;
            loaded.Lockdown();
            repo.Update(loaded);
            // No commit.
        }

        var current = await _host.Scope<DoorService, DoorView>(s => s.GetAsync(door.Id, default));
        Assert.Equal(DoorMode.Secure, current.Mode);
    }

    [Fact]
    public async Task Committed_state_survives_restart()
    {
        var directory = _host.DataDirectory;
        var door = await _host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest("Persisted", "Roof"), default));
        await _host.Scope<DoorService, DoorView>(s => s.LockdownAsync(door.Id, default));
        _host.Stop();

        using var restarted = new TestHost(dataDirectory: directory);
        var reloaded = await restarted.Scope<DoorService, DoorView>(s => s.GetAsync(door.Id, default));
        Assert.Equal("Persisted", reloaded.Name);
        Assert.Equal(DoorMode.Lockdown, reloaded.Mode);

        // Versions are restored too: an update after restart commits cleanly.
        var released = await restarted.Scope<DoorService, DoorView>(s => s.ReleaseLockdownAsync(door.Id, default));
        Assert.Equal(DoorMode.Secure, released.Mode);
    }

    [Fact]
    public async Task A_group_cannot_be_created_on_a_schedule_deleted_after_it_was_checked()
    {
        var schedule = await CreateScheduleAsync();

        // The group's request has checked that the schedule exists but not committed yet...
        using var creating = _host.CreateScope();
        await creating.ServiceProvider.GetRequiredService<IScheduleRepository>().GetAsync(schedule.Id, default);
        creating.ServiceProvider.GetRequiredService<IAccessGroupRepository>().Add(AccessGroup.Create(Guid.NewGuid(), "Staff", schedule.Id));

        // ...when the schedule is deleted.
        await _host.Scope<ScheduleService>(s => s.DeleteAsync(schedule.Id, default));

        var ex = await Assert.ThrowsAsync<NotFoundException>(() =>
            creating.ServiceProvider.GetRequiredService<IUnitOfWork>().CommitAsync(default));
        Assert.Equal("schedule.not_found", ex.Code);
        Assert.Empty((await _host.Scope<AccessGroupService, PagedResult<AccessGroupView>>(s =>
            s.ListAsync(PageRequest.From(null, null), default))).Items);
    }

    [Fact]
    public async Task A_schedule_cannot_be_deleted_once_a_group_started_using_it_after_the_check()
    {
        var schedule = await CreateScheduleAsync();

        // The delete has found no groups using the schedule but not committed yet...
        using var deleting = _host.CreateScope();
        var schedules = deleting.ServiceProvider.GetRequiredService<IScheduleRepository>();
        Assert.Empty(await deleting.ServiceProvider.GetRequiredService<IAccessGroupRepository>().ListByScheduleAsync(schedule.Id, default));
        schedules.Remove((await schedules.GetAsync(schedule.Id, default))!);

        // ...when a group starts using it.
        await _host.Scope<AccessGroupService, AccessGroupView>(s => s.CreateAsync(new AccessGroupRequest("Staff", schedule.Id), default));

        var ex = await Assert.ThrowsAsync<ConflictException>(() =>
            deleting.ServiceProvider.GetRequiredService<IUnitOfWork>().CommitAsync(default));
        Assert.Equal("schedule.in_use", ex.Code);
        Assert.Contains("Staff", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_door_cannot_be_added_to_a_group_after_the_door_was_deleted()
    {
        var schedule = await CreateScheduleAsync();
        var group = await _host.Scope<AccessGroupService, AccessGroupView>(s => s.CreateAsync(new AccessGroupRequest("Staff", schedule.Id), default));
        var door = await _host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest("A", null), default));

        using var adding = _host.CreateScope();
        var groups = adding.ServiceProvider.GetRequiredService<IAccessGroupRepository>();
        var loaded = (await groups.GetAsync(group.Id, default))!;
        loaded.AddDoor(door.Id);
        groups.Update(loaded);

        await _host.Scope<DoorService>(s => s.DeleteAsync(door.Id, default));

        var ex = await Assert.ThrowsAsync<NotFoundException>(() =>
            adding.ServiceProvider.GetRequiredService<IUnitOfWork>().CommitAsync(default));
        Assert.Equal("door.not_found", ex.Code);
    }

    [Fact]
    public async Task Deleting_a_group_fails_if_someone_joined_it_after_its_members_were_listed()
    {
        var schedule = await CreateScheduleAsync();
        var group = await _host.Scope<AccessGroupService, AccessGroupView>(s => s.CreateAsync(new AccessGroupRequest("Staff", schedule.Id), default));
        var person = await _host.Scope<CardholderService, CardholderView>(s =>
            s.CreateAsync(new CardholderRequest("Ada", "Lovelace", null, null, null), default));

        using var deleting = _host.CreateScope();
        var groups = deleting.ServiceProvider.GetRequiredService<IAccessGroupRepository>();
        Assert.Empty(await deleting.ServiceProvider.GetRequiredService<ICardholderRepository>().ListByAccessGroupAsync(group.Id, default));
        groups.Remove((await groups.GetAsync(group.Id, default))!);

        await _host.Scope<CardholderService, CardholderView>(s => s.JoinAccessGroupAsync(person.Id, group.Id, default));

        var ex = await Assert.ThrowsAsync<ConflictException>(() =>
            deleting.ServiceProvider.GetRequiredService<IUnitOfWork>().CommitAsync(default));
        Assert.Equal("concurrency_conflict", ex.Code);
        Assert.Equal([group.Id], (await _host.Scope<CardholderService, CardholderView>(s => s.GetAsync(person.Id, default))).AccessGroupIds);
    }

    [Fact]
    public async Task Stored_data_the_domain_rejects_is_a_server_error_not_a_validation_error()
    {
        var directory = _host.DataDirectory;
        var schedule = await CreateScheduleAsync();
        _host.Stop();

        // E.g. the store was moved to a host whose time-zone database lacks the schedule's zone.
        var path = Path.Combine(directory, "store.json");
        await File.WriteAllTextAsync(path, (await File.ReadAllTextAsync(path)).Replace("\"UTC\"", "\"Mars/Olympus_Mons\"", StringComparison.Ordinal));

        using var restarted = new TestHost(dataDirectory: directory);
        var ex = await Assert.ThrowsAsync<InvalidDataException>(() =>
            restarted.Scope<ScheduleService, ScheduleView>(s => s.GetAsync(schedule.Id, default)));
        Assert.Contains("timeZone.unknown", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_corrupt_store_file_stops_startup_instead_of_starting_empty()
    {
        var directory = _host.DataDirectory;
        await _host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest("A", null), default));
        _host.Stop();
        await File.WriteAllTextAsync(Path.Combine(directory, "store.json"), "{\"formatVersion\":1,\"collections\":{\"doors\":[{"); // truncated

        using var restarted = new TestHost(dataDirectory: directory);
        Assert.ThrowsAny<System.Text.Json.JsonException>(() => restarted.GetRequiredService<DocumentStore>());
    }

    private Task<ScheduleView> CreateScheduleAsync() =>
        _host.Scope<ScheduleService, ScheduleView>(s => s.CreateAsync(new ScheduleRequest("Always", "UTC", []), default));

    [Fact]
    public void Updating_an_aggregate_that_was_not_loaded_is_a_programming_error()
    {
        using var scope = _host.CreateScope();
        var repo = scope.ServiceProvider.GetRequiredService<IDoorRepository>();
        Assert.Throws<InvalidOperationException>(() => repo.Update(Door.Create(Guid.NewGuid(), "x", null)));
    }
}
