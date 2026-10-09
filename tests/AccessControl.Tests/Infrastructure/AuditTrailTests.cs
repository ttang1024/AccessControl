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
    public async Task Commands_that_change_nothing_leave_no_change_trail_entry()
    {
        var door = await CreateDoorAsync("A");
        await _host.Scope<DoorService, DoorView>(s => s.LockdownAsync(door.Id, default));
        await _host.Scope<DoorService, DoorView>(s => s.LockdownAsync(door.Id, default)); // already locked down
        await _host.Scope<DoorService, DoorView>(s => s.UpdateAsync(door.Id, new DoorRequest(" A ", null), default)); // same once trimmed

        var changes = await QueryChangesAsync(new ChangeAuditFilter(EntityId: door.Id));
        Assert.Equal([ChangeKind.Updated, ChangeKind.Created], changes.Items.Select(c => c.Kind));
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
    public async Task Queries_page_newest_first_across_segments_even_when_the_clock_moved_back()
    {
        using var host = new TestHost(settings: new Dictionary<string, string?> { ["Storage:AuditSegmentMaxBytes"] = "1" });
        var door = await host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest("A", null), default));
        var start = host.Clock.Now;
        var ids = new List<Guid>();
        foreach (var at in new[] { start, start.AddMinutes(1), start.AddMinutes(1), start.AddMinutes(-5) })
        {
            host.Clock.Now = at;
            ids.Add((await host.Scope<AccessService, AccessResponse>(s =>
                s.RequestAccessAsync(new AccessRequest(door.Id, "ABCD"), default))).EventId);
        }

        var page = await host.Scope<AccessService, PagedResult<AccessEventView>>(s =>
            s.QueryEventsAsync(new AccessEventFilter(), PageRequest.From(1, 2), default));

        // Newest first: ids[2] and ids[1] share a timestamp, so the later-appended one comes first.
        Assert.Equal(4, page.Total);
        Assert.Equal([ids[1], ids[0]], page.Items.Select(e => e.Id));
    }

    [Fact]
    public async Task Time_filtered_queries_stay_correct_once_segment_ranges_are_known()
    {
        using var host = new TestHost(settings: new Dictionary<string, string?> { ["Storage:AuditSegmentMaxBytes"] = "1" });
        var door = await host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest("A", null), default));
        var day1 = host.Clock.Now;
        for (var day = 0; day < 3; day++)
        {
            host.Clock.Now = day1.AddDays(day);
            await host.Scope<AccessService, AccessResponse>(s => s.RequestAccessAsync(new AccessRequest(door.Id, "ABCD"), default));
        }

        Task<PagedResult<AccessEventView>> QueryAsync(AccessEventFilter filter) =>
            host.Scope<AccessService, PagedResult<AccessEventView>>(s => s.QueryEventsAsync(filter, PageRequest.From(null, null), default));

        // Repeated so the second round runs against the remembered ranges of the archived segments.
        for (var round = 0; round < 2; round++)
        {
            var recent = await QueryAsync(new AccessEventFilter(From: day1.AddDays(1)));
            Assert.Equal([day1.AddDays(2), day1.AddDays(1)], recent.Items.Select(e => e.OccurredAt));

            var oldest = await QueryAsync(new AccessEventFilter(To: day1.AddDays(1)));
            Assert.Equal([day1], oldest.Items.Select(e => e.OccurredAt));

            Assert.Equal(3, (await QueryAsync(new AccessEventFilter())).Total);
            Assert.Equal(0, (await QueryAsync(new AccessEventFilter(From: day1.AddDays(3)))).Total);
        }
    }

    [Fact]
    public async Task Without_from_audit_queries_cover_the_default_window_before_to_or_now()
    {
        using var host = new TestHost(settings: new Dictionary<string, string?> { ["AuditQuery:DefaultDays"] = "7" });
        var start = host.Clock.Now;
        foreach (var daysAgo in new[] { 20, 10, 3 })
        {
            host.Clock.Now = start.AddDays(-daysAgo);
            await host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest($"{daysAgo} days ago", null), default));
        }

        host.Clock.Now = start;
        Task<PagedResult<ChangeAuditEntry>> ChangesAsync(DateTimeOffset? from, DateTimeOffset? to) =>
            host.Scope<AuditService, PagedResult<ChangeAuditEntry>>(s =>
                s.QueryChangesAsync(new ChangeAuditFilter(From: from, To: to), PageRequest.From(null, null), default));

        Assert.Equal([start.AddDays(-3)], (await ChangesAsync(null, null)).Items.Select(c => c.OccurredAt));
        Assert.Equal([start.AddDays(-10)], (await ChangesAsync(null, start.AddDays(-5))).Items.Select(c => c.OccurredAt));
        Assert.Equal(1, (await ChangesAsync(null, start.AddYears(1))).Total); // a future "to" counts back from now
        Assert.Equal(3, (await ChangesAsync(start.AddDays(-30), null)).Total); // an explicit "from" is honoured
    }

    [Fact]
    public async Task Access_event_queries_default_to_the_recent_window()
    {
        var door = await CreateDoorAsync("A");
        var start = _host.Clock.Now;
        _host.Clock.Now = start.AddDays(-31);
        await RequestAsync(door.Id);
        _host.Clock.Now = start;
        await RequestAsync(door.Id);

        var recent = await _host.Scope<AccessService, PagedResult<AccessEventView>>(s =>
            s.QueryEventsAsync(new AccessEventFilter(), PageRequest.From(null, null), default));
        var all = await _host.Scope<AccessService, PagedResult<AccessEventView>>(s =>
            s.QueryEventsAsync(new AccessEventFilter(From: start.AddDays(-60)), PageRequest.From(null, null), default));

        Assert.Equal([start], recent.Items.Select(e => e.OccurredAt));
        Assert.Equal(2, all.Total);
    }

    [Fact]
    public async Task Audit_queries_refuse_to_page_deeper_than_the_limit()
    {
        var page = PageRequest.From(PageRequest.MaxAuditOffset + 1, null);

        var error = await Assert.ThrowsAsync<RequestValidationException>(() =>
            _host.Scope<AccessService, PagedResult<AccessEventView>>(s => s.QueryEventsAsync(new AccessEventFilter(), page, default)));
        Assert.Equal("offset.too_deep", error.Code);
        await Assert.ThrowsAsync<RequestValidationException>(() =>
            _host.Scope<AuditService, PagedResult<ChangeAuditEntry>>(s => s.QueryChangesAsync(new ChangeAuditFilter(), page, default)));
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
    public async Task A_log_replaced_by_unchained_entries_is_detected_after_restart()
    {
        var directory = _host.DataDirectory;
        var door = await CreateDoorAsync("A");
        await RequestAsync(door.Id);
        _host.Stop();

        // Someone rewrites history as plain entries, which no hash covers.
        var forged = JsonSerializer.Serialize(new
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
        await File.WriteAllTextAsync(AccessLog, forged + "\n");

        using var restarted = new TestHost(dataDirectory: directory);
        var events = await restarted.Scope<AccessService, PagedResult<AccessEventView>>(s =>
            s.QueryEventsAsync(new AccessEventFilter(From: DateTimeOffset.UnixEpoch), PageRequest.From(null, null), default));
        Assert.Equal(0, events.Total); // never served as if it were audit data

        var report = (await restarted.Scope<AuditService, IReadOnlyList<AuditChainReport>>(s => s.VerifyAsync(default)))
            .Single(r => r.Log == "access-events");
        Assert.False(report.IsIntact);
        Assert.Contains("unchained entry", report.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Removing_the_oldest_segment_is_detected_without_a_retention_anchor()
    {
        using var host = new TestHost(settings: new Dictionary<string, string?> { ["Storage:AuditSegmentMaxBytes"] = "1" });
        var door = await host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest("A", null), default));
        for (var i = 0; i < 3; i++)
        {
            await host.Scope<AccessService, AccessResponse>(s => s.RequestAccessAsync(new AccessRequest(door.Id, "ABCD"), default));
        }

        host.Stop();
        File.Delete(Directory.GetFiles(host.DataDirectory, "access-events.*.jsonl").Order(StringComparer.Ordinal).First());

        using var restarted = new TestHost(dataDirectory: host.DataDirectory);
        var report = (await restarted.Scope<AuditService, IReadOnlyList<AuditChainReport>>(s => s.VerifyAsync(default)))
            .Single(r => r.Log == "access-events");
        Assert.False(report.IsIntact);
        Assert.Contains("oldest entries were removed", report.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_forged_retention_anchor_is_detected()
    {
        var settings = new Dictionary<string, string?>
        {
            ["Storage:AuditSegmentMaxBytes"] = "1",
            ["Storage:AuditRetentionDays"] = "30",
            ["Storage:AuditHmacKey"] = "secret-from-a-vault-0123456789abcdef",
        };
        using var host = new TestHost(settings: settings);
        var door = await host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest("A", null), default));
        for (var i = 0; i < 4; i++)
        {
            await host.Scope<AccessService, AccessResponse>(s => s.RequestAccessAsync(new AccessRequest(door.Id, "ABCD"), default));
        }

        var oldest = Directory.GetFiles(host.DataDirectory, "access-events.*.jsonl").Order(StringComparer.Ordinal).First();
        File.SetLastWriteTimeUtc(oldest, host.Clock.GetUtcNow().UtcDateTime.AddDays(-31));
        host.Stop();
        var retention = new TestHost(now: host.Clock.Now, dataDirectory: host.DataDirectory, settings: settings);
        retention.GetRequiredService<IAccessEventLog>(); // opening the log applies retention, which writes the anchor
        retention.Stop();

        // Someone deletes one more segment and moves the anchor forward without the key.
        var anchorPath = Path.Combine(host.DataDirectory, "access-events.anchor.json");
        var next = Directory.GetFiles(host.DataDirectory, "access-events.*.jsonl").Order(StringComparer.Ordinal).First();
        var lastLine = JsonDocument.Parse((await File.ReadAllLinesAsync(next)).Last()).RootElement;
        File.Delete(next);
        var anchor = JsonDocument.Parse(await File.ReadAllTextAsync(anchorPath)).RootElement;
        await File.WriteAllTextAsync(anchorPath, JsonSerializer.Serialize(new
        {
            sequence = lastLine.GetProperty("seq").GetInt64(),
            hash = lastLine.GetProperty("hash").GetString(),
            signature = anchor.GetProperty("signature").GetString(),
        }));

        using var restarted = new TestHost(now: host.Clock.Now, dataDirectory: host.DataDirectory, settings: settings);
        var report = (await restarted.Scope<AuditService, IReadOnlyList<AuditChainReport>>(s => s.VerifyAsync(default)))
            .Single(r => r.Log == "access-events");
        Assert.False(report.IsIntact);
        Assert.Contains("anchor does not match its signature", report.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Reports_carry_the_chain_head_for_off_host_monitoring()
    {
        var door = await CreateDoorAsync("A");
        await RequestAsync(door.Id);
        await RequestAsync(door.Id);

        var report = (await VerifyAsync()).Single(r => r.Log == "access-events");
        var lastLine = JsonDocument.Parse((await File.ReadAllLinesAsync(AccessLog)).Last()).RootElement;

        Assert.Equal(2, report.LastSequence);
        Assert.Equal(lastLine.GetProperty("hash").GetString(), report.LastHash);
    }

    [Fact]
    public async Task Concurrent_badge_reads_share_writes_and_keep_one_unbroken_chain()
    {
        var door = await CreateDoorAsync("A");

        var reads = Enumerable.Range(0, 50).Select(_ => Task.Run(() => RequestAsync(door.Id)));
        var responses = await Task.WhenAll(reads);

        var report = (await VerifyAsync()).Single(r => r.Log == "access-events");
        Assert.True(report.IsIntact, report.Problem);
        Assert.Equal(50, report.Entries);
        var lines = await File.ReadAllLinesAsync(AccessLog);
        Assert.Equal(
            responses.Select(r => r.EventId).Order(),
            lines.Select(l => JsonDocument.Parse(l).RootElement.GetProperty("data").GetProperty("id").GetGuid()).Order());
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
