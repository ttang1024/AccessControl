using AccessControl.Application.Abstractions;
using AccessControl.Application.Access;
using AccessControl.Application.Audit;
using AccessControl.Application.AccessGroups;
using AccessControl.Application.Cardholders;
using AccessControl.Application.Credentials;
using AccessControl.Application.Doors;
using AccessControl.Application.Errors;
using AccessControl.Application.Schedules;
using AccessControl.Domain.Access;
using Xunit;

namespace AccessControl.Tests.Application;

/// <summary>End-to-end through the real services and file-backed storage.</summary>
public sealed class AccessFlowTests : IDisposable
{
    // Wednesday 2026-10-07 09:00 NZDT.
    private readonly TestHostFixture _f = new(new DateTimeOffset(2026, 10, 7, 9, 0, 0, TimeSpan.FromHours(13)));

    public void Dispose() => _f.Dispose();

    [Fact]
    public async Task Member_is_granted_during_schedule_and_every_request_is_audited()
    {
        var site = await _f.SeedSiteAsync(workdayStart: "08:00", workdayEnd: "17:00");

        var granted = await _f.RequestAsync(site.DoorId, site.CardNumber);
        Assert.True(granted.Granted);

        _f.Host.Clock.Now = new DateTimeOffset(2026, 10, 7, 18, 0, 0, TimeSpan.FromHours(13));
        var afterHours = await _f.RequestAsync(site.DoorId, site.CardNumber);
        Assert.Equal(AccessDecisionReason.OutsideSchedule, afterHours.Reason);

        var events = await _f.Host.Scope<AccessService, PagedResult<AccessEventView>>(s =>
            s.QueryEventsAsync(new AccessEventFilter(DoorId: site.DoorId), PageRequest.From(null, null), default));

        Assert.Equal(2, events.Total);
        Assert.Equal(afterHours.EventId, events.Items[0].Id); // newest first
        Assert.Equal(site.CardholderId, events.Items[1].CardholderId);
    }

    [Fact]
    public async Task Unknown_and_malformed_cards_are_denied_and_audited()
    {
        var site = await _f.SeedSiteAsync();

        var unknown = await _f.RequestAsync(site.DoorId, "FFFF0000");
        _f.Host.Clock.Now = _f.Host.Clock.Now.AddSeconds(1);
        var malformed = await _f.RequestAsync(site.DoorId, "not-a-card");

        Assert.Equal(AccessDecisionReason.UnknownCredential, unknown.Reason);
        Assert.Equal(AccessDecisionReason.UnknownCredential, malformed.Reason);

        var events = await _f.Host.Scope<AccessService, PagedResult<AccessEventView>>(s =>
            s.QueryEventsAsync(new AccessEventFilter(Granted: false), PageRequest.From(null, null), default));
        Assert.Equal(2, events.Total);
        Assert.Equal("invalid:****card", events.Items[0].CardNumber);
    }

    [Fact]
    public async Task Unknown_door_is_rejected_without_audit()
    {
        await Assert.ThrowsAsync<NotFoundException>(() => _f.RequestAsync(Guid.NewGuid(), "ABCD"));

        var events = await _f.Host.Scope<AccessService, PagedResult<AccessEventView>>(s =>
            s.QueryEventsAsync(new AccessEventFilter(), PageRequest.From(null, null), default));
        Assert.Equal(0, events.Total);
    }

    [Fact]
    public async Task Revoking_a_card_takes_effect_on_the_next_read()
    {
        var site = await _f.SeedSiteAsync();
        Assert.True((await _f.RequestAsync(site.DoorId, site.CardNumber)).Granted);

        await _f.Host.Scope<CredentialService>(s => s.RevokeAsync(site.CredentialId, default));

        Assert.Equal(AccessDecisionReason.CredentialNotActive, (await _f.RequestAsync(site.DoorId, site.CardNumber)).Reason);
    }

    [Fact]
    public async Task Card_numbers_are_unique_across_spellings()
    {
        var site = await _f.SeedSiteAsync();
        var other = await _f.Host.Scope<CardholderService, CardholderView>(s =>
            s.CreateAsync(new CardholderRequest("Alan", "Turing", null, null, null), default));

        var ex = await Assert.ThrowsAsync<ConflictException>(() =>
            _f.Host.Scope<CredentialService, CredentialView>(s =>
                s.IssueAsync(other.Id, new IssueCredentialRequest(site.CardNumber.ToLowerInvariant(), null), default)));
        Assert.Equal("credential.duplicate_card_number", ex.Code);
    }

    [Fact]
    public async Task Decisions_are_counted_by_outcome_and_reason()
    {
        var site = await _f.SeedSiteAsync();
        var seen = new System.Collections.Concurrent.ConcurrentBag<(string? Outcome, string? Reason)>();
        using var listener = new System.Diagnostics.Metrics.MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == AccessService.MeterName && instrument.Name == "accesscontrol.access.decisions")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            var values = tags.ToArray().ToDictionary(t => t.Key, t => t.Value as string);
            seen.Add((values.GetValueOrDefault("outcome"), values.GetValueOrDefault("reason")));
        });
        listener.Start();

        await _f.RequestAsync(site.DoorId, site.CardNumber);
        await _f.RequestAsync(site.DoorId, "FFFF");

        // Other tests run in parallel and use the same meter, so look for ours rather than counting.
        Assert.Contains(("granted", "Granted"), seen);
        Assert.Contains(("denied", "UnknownCredential"), seen);
    }

    [Fact]
    public async Task Lists_are_paged_by_name()
    {
        foreach (var name in new[] { "Cellar", "attic", "Basement" })
        {
            await _f.Host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest(name, null), default));
        }

        var page = await _f.Host.Scope<DoorService, PagedResult<DoorView>>(s => s.ListAsync(PageRequest.From(1, 1), default));

        Assert.Equal(3, page.Total);
        Assert.Equal(["Basement"], page.Items.Select(d => d.Name));
    }

    [Fact]
    public async Task Responses_never_contain_a_full_card_number()
    {
        var site = await _f.SeedSiteAsync();
        await _f.RequestAsync(site.DoorId, site.CardNumber);

        var credential = await _f.Host.Scope<CredentialService, CredentialView>(s => s.GetAsync(site.CredentialId, default));
        var events = await _f.Host.Scope<AccessService, PagedResult<AccessEventView>>(s =>
            s.QueryEventsAsync(new AccessEventFilter(), PageRequest.From(null, null), default));
        var issued = await _f.Host.Scope<AuditService, PagedResult<ChangeAuditEntry>>(s =>
            s.QueryChangesAsync(new ChangeAuditFilter(EntityId: site.CredentialId), PageRequest.From(null, null), default));

        Assert.Equal("****1234", credential.CardNumber);
        Assert.Equal("****1234", events.Items.Single().CardNumber);
        Assert.Equal("****1234", issued.Items.Single().After!.Value.GetProperty("cardNumber").GetString());
    }

    [Theory]
    [InlineData("ABCD1234", "****1234")]
    [InlineData("ABCD", "****CD")]
    [InlineData("A", "****")]
    [InlineData("invalid:", "invalid:****")]
    public void Masking_shows_at_most_four_and_never_more_than_half(string value, string expected) =>
        Assert.Equal(expected, CardNumberMask.Mask(value));

    [Fact]
    public async Task Deleting_an_access_group_removes_membership_atomically()
    {
        var site = await _f.SeedSiteAsync();

        await _f.Host.Scope<AccessGroupService>(s => s.DeleteAsync(site.GroupId, default));

        var cardholder = await _f.Host.Scope<CardholderService, CardholderView>(s => s.GetAsync(site.CardholderId, default));
        Assert.Empty(cardholder.AccessGroupIds);
        Assert.Equal(AccessDecisionReason.NoPermissionForDoor, (await _f.RequestAsync(site.DoorId, site.CardNumber)).Reason);
    }

    [Fact]
    public async Task Schedules_and_doors_in_use_cannot_be_deleted()
    {
        var site = await _f.SeedSiteAsync();

        var scheduleEx = await Assert.ThrowsAsync<ConflictException>(() =>
            _f.Host.Scope<ScheduleService>(s => s.DeleteAsync(site.ScheduleId, default)));
        var doorEx = await Assert.ThrowsAsync<ConflictException>(() =>
            _f.Host.Scope<DoorService>(s => s.DeleteAsync(site.DoorId, default)));

        Assert.Equal("schedule.in_use", scheduleEx.Code);
        Assert.Equal("door.in_use", doorEx.Code);
    }

    [Fact]
    public async Task Joining_a_missing_group_is_not_found()
    {
        var site = await _f.SeedSiteAsync();
        await Assert.ThrowsAsync<NotFoundException>(() =>
            _f.Host.Scope<CardholderService, CardholderView>(s =>
                s.JoinAccessGroupAsync(site.CardholderId, Guid.NewGuid(), default)));
    }
}

/// <summary>Seeds a minimal site: one door, one schedule, one group, one cardholder with one card.</summary>
internal sealed class TestHostFixture(DateTimeOffset now) : IDisposable
{
    public Support.TestHost Host { get; } = new(now);

    public void Dispose() => Host.Dispose();

    public Task<AccessResponse> RequestAsync(Guid doorId, string cardNumber) =>
        Host.Scope<AccessService, AccessResponse>(s => s.RequestAccessAsync(new AccessRequest(doorId, cardNumber), default));

    public const string IssuedCardNumber = "AB:CD:12:34";

    public async Task<SeededSite> SeedSiteAsync(string workdayStart = "00:00", string workdayEnd = "24:00")
    {
        var schedule = await Host.Scope<ScheduleService, ScheduleView>(s => s.CreateAsync(
            new ScheduleRequest(
                "Workdays",
                "Pacific/Auckland",
                [.. new[] { DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday }
                    .Select(d => new TimeWindowDto(d, workdayStart, workdayEnd))]),
            default));

        var door = await Host.Scope<DoorService, DoorView>(s => s.CreateAsync(new DoorRequest("Front door", "Lobby"), default));
        var group = await Host.Scope<AccessGroupService, AccessGroupView>(s =>
            s.CreateAsync(new AccessGroupRequest("Staff", schedule.Id), default));
        await Host.Scope<AccessGroupService, AccessGroupView>(s => s.AddDoorAsync(group.Id, door.Id, default));

        var cardholder = await Host.Scope<CardholderService, CardholderView>(s =>
            s.CreateAsync(new CardholderRequest("Ada", "Lovelace", "E-1", null, null), default));
        await Host.Scope<CardholderService, CardholderView>(s => s.JoinAccessGroupAsync(cardholder.Id, group.Id, default));
        var credential = await Host.Scope<CredentialService, CredentialView>(s =>
            s.IssueAsync(cardholder.Id, new IssueCredentialRequest(IssuedCardNumber, null), default));

        // The API only returns masked card numbers, so badge reads use the number that was issued.
        return new SeededSite(door.Id, schedule.Id, group.Id, cardholder.Id, credential.Id, IssuedCardNumber);
    }
}

internal sealed record SeededSite(
    Guid DoorId, Guid ScheduleId, Guid GroupId, Guid CardholderId, Guid CredentialId, string CardNumber);
