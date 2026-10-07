using AccessControl.Application.Abstractions;
using AccessControl.Application.Doors;
using AccessControl.Application.Errors;
using AccessControl.Domain.Doors;
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
    public void Updating_an_aggregate_that_was_not_loaded_is_a_programming_error()
    {
        using var scope = _host.CreateScope();
        var repo = scope.ServiceProvider.GetRequiredService<IDoorRepository>();
        Assert.Throws<InvalidOperationException>(() => repo.Update(Door.Create(Guid.NewGuid(), "x", null)));
    }
}
