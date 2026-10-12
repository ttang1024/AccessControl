using AccessControl.Application.Abstractions;
using AccessControl.Application.Access;
using AccessControl.Application.AccessGroups;
using AccessControl.Application.Audit;
using AccessControl.Application.Cardholders;
using AccessControl.Application.Doors;
using AccessControl.Application.Schedules;
using AccessControl.Domain.Doors;
using AccessControl.Infrastructure.Persistence;
using AccessControl.Infrastructure.Storage;
using AccessControl.Tests.Support;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace AccessControl.Tests.Infrastructure;

/// <summary>The change log as write-ahead log: crash recovery, the data-directory lock, migrations and failed writes.</summary>
public sealed class StorageRecoveryTests : IDisposable
{
    private readonly TestHost _host = new();
    private readonly List<string> _copies = [];

    public void Dispose()
    {
        _host.Dispose();
        foreach (var copy in _copies.Where(Directory.Exists))
        {
            Directory.Delete(copy, recursive: true);
        }
    }

    [Fact]
    public void A_second_instance_cannot_open_the_same_data_directory()
    {
        _host.GetRequiredService<DocumentStore>();

        var second = new TestHost(dataDirectory: _host.DataDirectory);
        try
        {
            var ex = Assert.Throws<InvalidOperationException>(() => second.GetRequiredService<DocumentStore>());
            Assert.Contains("in use by another process", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            second.Stop(); // not Dispose: that would delete the first host's directory
        }
    }

    [Fact]
    public async Task Commits_after_the_last_checkpoint_are_replayed_after_a_crash()
    {
        using var host = new TestHost(settings: new Dictionary<string, string?> { ["Storage:CheckpointEveryCommits"] = "3" });
        var doors = new List<DoorView>();
        for (var i = 0; i < 5; i++)
        {
            doors.Add(await host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest($"Door {i}", null), default)));
        }

        await host.Scope<DoorService, DoorView>(s => s.LockdownAsync(doors[4].Id, null, default));

        // The checkpoint holds the first three commits; the other three exist only in the change log.
        var crashed = CrashCopy(host.DataDirectory);
        using var recovered = new TestHost(dataDirectory: crashed);
        var listed = await recovered.Scope<DoorService, PagedResult<DoorView>>(s => s.SearchAsync(null, PageRequest.From(null, null), default));

        Assert.Equal(5, listed.Total);
        var locked = listed.Items.Single(d => d.Id == doors[4].Id);
        Assert.Equal(DoorMode.Lockdown, locked.Mode);
        Assert.Equal(2, locked.Version);

        // Versions were replayed too: the next change commits cleanly and the trail still verifies.
        await recovered.Scope<DoorService, DoorView>(s => s.ReleaseLockdownAsync(doors[4].Id, 2, default));
        Assert.All(
            await recovered.Scope<AuditService, IReadOnlyList<AuditChainReport>>(s => s.VerifyAsync(default)),
            r => Assert.True(r.IsIntact, r.Problem));
    }

    [Fact]
    public async Task A_commit_cut_off_by_a_crash_is_not_replayed()
    {
        var schedule = await _host.Scope<ScheduleService, ScheduleView>(s => s.CreateAsync(new ScheduleRequest("Always", "UTC", []), default));
        var group = await _host.Scope<AccessGroupService, AccessGroupView>(s => s.CreateAsync(new AccessGroupRequest("Staff", schedule.Id), default));
        var ada = await _host.Scope<CardholderService, CardholderView>(s => s.CreateAsync(new CardholderRequest("Ada", "Lovelace", null, null, null), default));
        await _host.Scope<CardholderService, CardholderView>(s => s.JoinAccessGroupAsync(ada.Id, group.Id, null, default));

        // Deleting the group is one commit of two entries (Ada leaves, the group goes); the crash cuts off the second.
        await _host.Scope<AccessGroupService>(s => s.DeleteAsync(group.Id, null, default));
        var crashed = CrashCopy(_host.DataDirectory);
        var changes = Path.Combine(crashed, "changes.jsonl");
        var lines = await File.ReadAllLinesAsync(changes);
        await File.WriteAllTextAsync(changes, string.Join('\n', lines[..^1]) + "\n" + lines[^1][..20]);

        using var recovered = new TestHost(dataDirectory: crashed);
        Assert.Equal("Staff", (await recovered.Scope<AccessGroupService, AccessGroupView>(s => s.GetAsync(group.Id, default))).Name);
        Assert.Equal([group.Id], (await recovered.Scope<CardholderService, CardholderView>(s => s.GetAsync(ada.Id, default))).AccessGroupIds);
    }

    [Fact]
    public async Task A_change_log_altered_after_the_checkpoint_stops_startup()
    {
        await _host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest("Front", null), default));
        await _host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest("Back", null), default));

        var crashed = CrashCopy(_host.DataDirectory);
        var changes = Path.Combine(crashed, "changes.jsonl");
        await File.WriteAllTextAsync(changes, (await File.ReadAllTextAsync(changes)).Replace("\"Back\"", "\"Vault\"", StringComparison.Ordinal));

        var recovered = new TestHost(dataDirectory: crashed);
        try
        {
            var ex = Assert.Throws<InvalidDataException>(() => recovered.GetRequiredService<DocumentStore>());
            Assert.Contains("missing or were altered", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            recovered.Stop();
        }
    }

    [Fact]
    public async Task A_failed_audit_append_is_a_failure_and_leaves_the_chain_intact()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var door = await _host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest("Front", null), default));
        await RequestAsync(door.Id);

        var active = Path.Combine(_host.DataDirectory, "access-events.jsonl");
        File.SetUnixFileMode(active, UnixFileMode.UserRead);
        try
        {
            // The read cannot be audited, so it is not answered: the controller treats the error as a denial.
            await Assert.ThrowsAnyAsync<UnauthorizedAccessException>(() => RequestAsync(door.Id));
        }
        finally
        {
            File.SetUnixFileMode(active, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        await RequestAsync(door.Id);
        var report = (await _host.Scope<AuditService, IReadOnlyList<AuditChainReport>>(s => s.VerifyAsync(default)))
            .Single(r => r.Log == "access-events");
        Assert.True(report.IsIntact, report.Problem);
        Assert.Equal(2, report.Entries);
    }

    private Task<AccessResponse> RequestAsync(Guid doorId) =>
        _host.Scope<AccessService, AccessResponse>(s =>
            s.RequestAccessAsync(new AccessRequest(doorId, "ABCD"), default));

    /// <summary>The data directory as a crash would leave it: whatever is on disk now, without a final checkpoint.</summary>
    private string CrashCopy(string source)
    {
        var copy = Path.Combine(Path.GetTempPath(), "acs-crash-" + Guid.NewGuid().ToString("N"));
        _copies.Add(copy);
        Directory.CreateDirectory(copy);
        foreach (var file in Directory.GetFiles(source).Where(f => Path.GetFileName(f) != DataDirectoryLock.FileName))
        {
            File.Copy(file, Path.Combine(copy, Path.GetFileName(file)));
        }

        return copy;
    }
}
