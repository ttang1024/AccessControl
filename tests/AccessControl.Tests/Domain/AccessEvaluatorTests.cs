using AccessControl.Domain.Access;
using AccessControl.Domain.AccessGroups;
using AccessControl.Domain.Cardholders;
using AccessControl.Domain.Credentials;
using AccessControl.Domain.Doors;
using AccessControl.Domain.Schedules;
using Xunit;

namespace AccessControl.Tests.Domain;

public sealed class AccessEvaluatorTests
{
    // Wednesday 2026-10-07 10:00 UTC.
    private static readonly DateTimeOffset Now = new(2026, 10, 7, 10, 0, 0, TimeSpan.Zero);

    private readonly Door _door = Door.Create(Guid.NewGuid(), "Lab", null);
    private readonly Cardholder _cardholder = Cardholder.Create(Guid.NewGuid(), "Grace", "Hopper");
    private readonly Schedule _always;
    private readonly Schedule _never;
    private readonly AccessGroup _group;
    private readonly Credential _credential;

    public AccessEvaluatorTests()
    {
        var allDay = Enum.GetValues<DayOfWeek>()
            .Select(d => WeeklyTimeWindow.Create(d, TimeSpan.Zero, TimeSpan.FromHours(24)));
        _always = Schedule.Create(Guid.NewGuid(), "24/7", "UTC", allDay);
        _never = Schedule.Create(Guid.NewGuid(), "Never", "UTC", []);

        _group = AccessGroup.Create(Guid.NewGuid(), "Lab users", _always.Id);
        _group.AddDoor(_door.Id);
        _cardholder.JoinAccessGroup(_group.Id);

        _credential = Credential.Issue(Guid.NewGuid(), _cardholder.Id, CardNumber.Parse("C0FFEE"), Now.AddDays(-1), null);
    }

    private AccessDecision Evaluate(
        Credential? credential = null,
        Cardholder? cardholder = null,
        IReadOnlyCollection<AccessGroup>? groups = null,
        bool omitCredential = false,
        bool omitCardholder = false) =>
        AccessEvaluator.Evaluate(new AccessRequestContext(
            _door,
            omitCredential ? null : credential ?? _credential,
            omitCardholder ? null : cardholder ?? _cardholder,
            groups ?? [_group],
            new Dictionary<Guid, Schedule> { [_always.Id] = _always, [_never.Id] = _never },
            Now));

    [Fact]
    public void Grants_when_everything_is_in_order()
    {
        Assert.Equal(AccessDecision.Grant, Evaluate());
    }

    [Fact]
    public void Lockdown_overrides_valid_permissions()
    {
        _door.Lockdown();
        Assert.Equal(AccessDecisionReason.DoorInLockdown, Evaluate().Reason);
    }

    [Fact]
    public void Unknown_credential_is_denied()
    {
        Assert.Equal(AccessDecisionReason.UnknownCredential, Evaluate(omitCredential: true).Reason);
    }

    [Fact]
    public void Suspended_credential_is_denied()
    {
        _credential.Suspend();
        Assert.Equal(AccessDecisionReason.CredentialNotActive, Evaluate().Reason);
    }

    [Fact]
    public void Expired_credential_is_denied()
    {
        _credential.ChangeExpiry(Now);
        Assert.Equal(AccessDecisionReason.CredentialExpired, Evaluate().Reason);
    }

    [Fact]
    public void Missing_or_mismatched_cardholder_is_denied()
    {
        Assert.Equal(AccessDecisionReason.CardholderNotFound, Evaluate(omitCardholder: true).Reason);

        var someoneElse = Cardholder.Create(Guid.NewGuid(), "Not", "Owner");
        Assert.Equal(AccessDecisionReason.CardholderNotFound, Evaluate(cardholder: someoneElse).Reason);
    }

    [Fact]
    public void Disabled_cardholder_is_denied()
    {
        _cardholder.Disable();
        Assert.Equal(AccessDecisionReason.CardholderDisabled, Evaluate().Reason);
    }

    [Fact]
    public void Cardholder_outside_validity_period_is_denied()
    {
        _cardholder.SetValidityPeriod(Now.AddDays(1), null);
        Assert.Equal(AccessDecisionReason.CardholderOutsideValidityPeriod, Evaluate().Reason);

        _cardholder.SetValidityPeriod(null, Now);
        Assert.Equal(AccessDecisionReason.CardholderOutsideValidityPeriod, Evaluate().Reason);
    }

    [Fact]
    public void Group_without_the_door_is_denied()
    {
        _group.RemoveDoor(_door.Id);
        Assert.Equal(AccessDecisionReason.NoPermissionForDoor, Evaluate().Reason);
    }

    [Fact]
    public void Groups_the_cardholder_does_not_belong_to_are_ignored()
    {
        _cardholder.LeaveAccessGroup(_group.Id);
        Assert.Equal(AccessDecisionReason.NoPermissionForDoor, Evaluate().Reason);
    }

    [Fact]
    public void Outside_schedule_is_denied()
    {
        _group.ChangeSchedule(_never.Id);
        Assert.Equal(AccessDecisionReason.OutsideSchedule, Evaluate().Reason);
    }

    [Fact]
    public void Missing_schedule_fails_closed()
    {
        _group.ChangeSchedule(Guid.NewGuid());
        Assert.Equal(AccessDecisionReason.OutsideSchedule, Evaluate().Reason);
    }

    [Fact]
    public void Any_group_in_schedule_grants()
    {
        var nightShift = AccessGroup.Create(Guid.NewGuid(), "Night", _never.Id);
        nightShift.AddDoor(_door.Id);
        _cardholder.JoinAccessGroup(nightShift.Id);

        Assert.True(Evaluate(groups: [nightShift, _group]).IsGranted);
    }
}
