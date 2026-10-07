namespace AccessControl.Api.Auth;

public static class Roles
{
    /// <summary>Full control: everything below, plus doors, schedules, access groups and releasing lockdowns.</summary>
    public const string Admin = "Admin";

    /// <summary>Day-to-day enrolment: cardholders, credentials, group membership; may lock doors down but not release them.</summary>
    public const string Operator = "Operator";

    /// <summary>Read-only: configuration, the access-event trail and the change trail.</summary>
    public const string Auditor = "Auditor";

    /// <summary>Door controllers: may only submit badge reads, and only for their assigned doors.</summary>
    public const string DoorController = "DoorController";

    public static readonly IReadOnlyList<string> All = [Admin, Operator, Auditor, DoorController];
}
