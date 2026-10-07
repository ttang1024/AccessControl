using System.Text.Json;
using AccessControl.Application.Abstractions;
using AccessControl.Application.Access;
using AccessControl.Application.Audit;
using AccessControl.Application.Doors;
using AccessControl.Application.Errors;
using AccessControl.Tests.Support;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AccessControl.Tests.Infrastructure;

public sealed class AuditTrailTests : IDisposable
{
    private readonly TestHost _host = new();

    public void Dispose() => _host.Dispose();

    private string AccessLog => Path.Combine(_host.DataDirectory, "access-events.jsonl");

    private string ChangeLog => Path.Combine(_host.DataDirectory, "changes.jsonl");

    [Fact]
    public async Task Commits_record_actor_kind_and_before_after_state()
    {
        _host.Actor.Actor = "alice";
        var door = await CreateDoorAsync("Front");
        _host.Actor.Actor = "bob";
        await _host.Scope<DoorService, DoorView>(s => s.LockdownAsync(door.Id, default));
        await _host.Scope<DoorService>(s => s.DeleteAsync(door.Id, default));

        var changes = await QueryChangesAsync(new ChangeAuditFilter(EntityId: door.Id));

        Assert.Equal([ChangeKind.Deleted, ChangeKind.Updated, ChangeKind.Created], changes.Items.Select(c => c.Kind));
        Assert.Equal(["bob", "bob", "alice"], changes.Items.Select(c => c.Actor));
        Assert.All(changes.Items, c => Assert.Equal("doors", c.EntityType));

        var lockdown = changes.Items[1];
        Assert.Equal("Secure", lockdown.Before!.Value.GetProperty("mode").GetString());
        Assert.Equal("Lockdown", lockdown.After!.Value.GetProperty("mode").GetString());
        Assert.Null(changes.Items[0].After);
        Assert.Null(changes.Items[2].Before);
    }

    [Fact]
    public async Task A_rejected_commit_records_nothing()
    {
        var door = await CreateDoorAsync("A");
        using var first = _host.CreateScope();
        using var second = _host.CreateScope();
        var a = (await first.ServiceProvider.GetRequiredService<IDoorRepository>().GetAsync(door.Id, default))!;
        var b = (await second.ServiceProvider.GetRequiredService<IDoorRepository>().GetAsync(door.Id, default))!;

        a.Lockdown();
        first.ServiceProvider.GetRequiredService<IDoorRepository>().Update(a);
        await first.ServiceProvider.GetRequiredService<IUnitOfWork>().CommitAsync(default);
        b.UpdateDetails("Loser", null);
        second.ServiceProvider.GetRequiredService<IDoorRepository>().Update(b);
        await Assert.ThrowsAsync<ConflictException>(() =>
            second.ServiceProvider.GetRequiredService<IUnitOfWork>().CommitAsync(default));

        var changes = await QueryChangesAsync(new ChangeAuditFilter(EntityId: door.Id));
        Assert.Equal(2, changes.Total); // create + lockdown only
    }

    [Fact]
    public async Task Untouched_logs_verify_as_intact()
    {
        var door = await CreateDoorAsync("A");
        await RequestAsync(door.Id);
        await RequestAsync(door.Id);

        var reports = await VerifyAsync();

        Assert.All(reports, r => Assert.True(r.IsIntact, r.Problem));
        Assert.Equal(2, reports.Single(r => r.Log == "access-events").Entries);
        Assert.Equal(1, reports.Single(r => r.Log == "changes").Entries);
    }

    [Fact]
    public async Task Editing_an_entry_is_detected()
    {
        var door = await CreateDoorAsync("A");
        await RequestAsync(door.Id);
        await RequestAsync(door.Id);

        var lines = await File.ReadAllLinesAsync(AccessLog);
        lines[0] = lines[0].Replace("\"granted\":false", "\"granted\":true", StringComparison.Ordinal);
        await File.WriteAllLinesAsync(AccessLog, lines);

        var report = (await VerifyAsync()).Single(r => r.Log == "access-events");
        Assert.False(report.IsIntact);
        Assert.Contains("modified", report.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Removing_an_entry_is_detected()
    {
        var door = await CreateDoorAsync("A");
        for (var i = 0; i < 3; i++)
        {
            await RequestAsync(door.Id);
        }

        var lines = (await File.ReadAllLinesAsync(AccessLog)).ToList();
        lines.RemoveAt(1);
        await File.WriteAllLinesAsync(AccessLog, lines);

        var report = (await VerifyAsync()).Single(r => r.Log == "access-events");
        Assert.False(report.IsIntact);
        Assert.Contains("removed, inserted or reordered", report.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Removing_the_newest_entries_is_detected_while_running()
    {
        var door = await CreateDoorAsync("A");
        await RequestAsync(door.Id);
        await RequestAsync(door.Id);

        var lines = await File.ReadAllLinesAsync(AccessLog);
        await File.WriteAllLinesAsync(AccessLog, lines[..1]);

        var report = (await VerifyAsync()).Single(r => r.Log == "access-events");
        Assert.False(report.IsIntact);
        Assert.Contains("newest entries were removed", report.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public async Task With_a_key_a_recomputed_chain_is_still_detected()
    {
        using var keyed = new TestHost(settings: new Dictionary<string, string?> { ["Storage:AuditHmacKey"] = "secret-from-a-vault" });
        await keyed.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest("A", null), default));
        keyed.Stop();

        // Someone with file access but not the key edits the entry and recomputes the hashes without a key.
        using (var unkeyed = new TestHost(dataDirectory: Path.Combine(Path.GetTempPath(), "acs-tests-" + Guid.NewGuid().ToString("N"))))
        {
            await unkeyed.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest("Forged", null), default));
            unkeyed.Stop();
            File.Copy(Path.Combine(unkeyed.DataDirectory, "changes.jsonl"), Path.Combine(keyed.DataDirectory, "changes.jsonl"), overwrite: true);
        }

        using var restarted = new TestHost(
            dataDirectory: keyed.DataDirectory,
            settings: new Dictionary<string, string?> { ["Storage:AuditHmacKey"] = "secret-from-a-vault" });
        var report = (await restarted.Scope<AuditService, IReadOnlyList<AuditChainReport>>(s => s.VerifyAsync(default)))
            .Single(r => r.Log == "changes");
        Assert.False(report.IsIntact);
    }

    [Fact]
    public async Task A_torn_line_is_skipped_and_the_chain_continues_after_restart()
    {
        var directory = _host.DataDirectory;
        var door = await CreateDoorAsync("A");
        await RequestAsync(door.Id);
        _host.Stop();
        await File.AppendAllTextAsync(AccessLog, "{\"seq\":2,\"prev\":\"AB"); // crash mid-write

        using var restarted = new TestHost(dataDirectory: directory);
        await restarted.Scope<AccessService, AccessResponse>(s =>
            s.RequestAccessAsync(new AccessRequest(door.Id, "ABCD"), default));

        var report = (await restarted.Scope<AuditService, IReadOnlyList<AuditChainReport>>(s => s.VerifyAsync(default)))
            .Single(r => r.Log == "access-events");
        Assert.True(report.IsIntact, report.Problem);
        Assert.Equal(2, report.Entries);
        Assert.Equal(1, report.SkippedLines);

        var events = await restarted.Scope<AccessService, PagedResult<AccessEventView>>(s =>
            s.QueryEventsAsync(new AccessEventFilter(), PageRequest.From(null, null), default));
        Assert.Equal(2, events.Total);
    }

    [Fact]
    public async Task Rotated_segments_keep_the_chain_and_are_still_queried()
    {
        using var host = new TestHost(settings: new Dictionary<string, string?> { ["Storage:AuditSegmentMaxBytes"] = "1" });
        var door = await host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest("A", null), default));
        for (var i = 0; i < 3; i++)
        {
            await host.Scope<AccessService, AccessResponse>(s => s.RequestAccessAsync(new AccessRequest(door.Id, "ABCD"), default));
        }

        Assert.Equal(2, Directory.GetFiles(host.DataDirectory, "access-events.*.jsonl").Length);

        var events = await host.Scope<AccessService, PagedResult<AccessEventView>>(s =>
            s.QueryEventsAsync(new AccessEventFilter(), PageRequest.From(null, null), default));
        Assert.Equal(3, events.Total);

        var report = (await host.Scope<AuditService, IReadOnlyList<AuditChainReport>>(s => s.VerifyAsync(default)))
            .Single(r => r.Log == "access-events");
        Assert.True(report.IsIntact, report.Problem);
        Assert.Equal(3, report.Entries);
    }

    [Fact]
    public async Task Retention_removes_old_segments_and_the_rest_still_verifies()
    {
        var settings = new Dictionary<string, string?>
        {
            ["Storage:AuditSegmentMaxBytes"] = "1",
            ["Storage:AuditRetentionDays"] = "30",
        };
        using var host = new TestHost(settings: settings);
        var door = await host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest("A", null), default));
        for (var i = 0; i < 3; i++)
        {
            await host.Scope<AccessService, AccessResponse>(s => s.RequestAccessAsync(new AccessRequest(door.Id, "ABCD"), default));
        }

        var oldest = Directory.GetFiles(host.DataDirectory, "access-events.*.jsonl").Order(StringComparer.Ordinal).First();
        File.SetLastWriteTimeUtc(oldest, host.Clock.GetUtcNow().UtcDateTime.AddDays(-31));
        host.Stop();

        using var restarted = new TestHost(now: host.Clock.Now, dataDirectory: host.DataDirectory, settings: settings);
        var report = (await restarted.Scope<AuditService, IReadOnlyList<AuditChainReport>>(s => s.VerifyAsync(default)))
            .Single(r => r.Log == "access-events");
        Assert.False(File.Exists(oldest));
        Assert.True(report.IsIntact, report.Problem);
        Assert.Equal(2, report.FirstSequence);
    }

    [Fact]
    public async Task Entries_written_before_chaining_are_still_read_and_reported_as_legacy()
    {
        var directory = _host.DataDirectory;
        var door = await CreateDoorAsync("A");
        _host.Stop();
        var legacy = JsonSerializer.Serialize(new
        {
            id = Guid.NewGuid(),
            occurredAt = DateTimeOffset.UnixEpoch,
            doorId = door.Id,
            cardNumber = "ABCD",
            credentialId = (Guid?)null,
            cardholderId = (Guid?)null,
            granted = false,
            reason = "UnknownCredential",
        });
        await File.WriteAllTextAsync(AccessLog, legacy + "\n");

        using var restarted = new TestHost(dataDirectory: directory);
        await restarted.Scope<AccessService, AccessResponse>(s => s.RequestAccessAsync(new AccessRequest(door.Id, "ABCD"), default));

        var events = await restarted.Scope<AccessService, PagedResult<AccessEventView>>(s =>
            s.QueryEventsAsync(new AccessEventFilter(), PageRequest.From(null, null), default));
        Assert.Equal(2, events.Total);
        var report = (await restarted.Scope<AuditService, IReadOnlyList<AuditChainReport>>(s => s.VerifyAsync(default)))
            .Single(r => r.Log == "access-events");
        Assert.True(report.IsIntact, report.Problem);
        Assert.Equal(1, report.LegacyEntries);
        Assert.Equal(1, report.Entries);
    }

    [Fact]
    public async Task Reads_within_a_unit_of_work_see_one_snapshot()
    {
        var door = await CreateDoorAsync("Before");

        using var reader = _host.CreateScope();
        var doors = reader.ServiceProvider.GetRequiredService<IDoorRepository>();
        Assert.Equal("Before", (await doors.GetAsync(door.Id, default))!.Name);

        await _host.Scope<DoorService, DoorView>(s => s.UpdateAsync(door.Id, new DoorRequest("After", null), default));
        var created = await CreateDoorAsync("New");

        // Same unit of work: still the state as of its first read.
        Assert.Equal("Before", (await doors.GetAsync(door.Id, default))!.Name);
        Assert.Null(await doors.GetAsync(created.Id, default));
    }

    private Task<DoorView> CreateDoorAsync(string name) =>
        _host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest(name, null), default));

    private Task<AccessResponse> RequestAsync(Guid doorId) =>
        _host.Scope<AccessService, AccessResponse>(s => s.RequestAccessAsync(new AccessRequest(doorId, "FFFF"), default));

    private Task<PagedResult<ChangeAuditEntry>> QueryChangesAsync(ChangeAuditFilter filter) =>
        _host.Scope<AuditService, PagedResult<ChangeAuditEntry>>(s => s.QueryChangesAsync(filter, PageRequest.From(null, null), default));

    private Task<IReadOnlyList<AuditChainReport>> VerifyAsync() =>
        _host.Scope<AuditService, IReadOnlyList<AuditChainReport>>(s => s.VerifyAsync(default));
}
