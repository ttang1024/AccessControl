namespace AccessControl.Application.Errors;

/// <summary>
/// Resource names used in errors. They form the stable error codes (e.g. <c>door.not_found</c>, <c>schedule.in_use</c>),
/// so they are part of the API contract: never rename one.
/// </summary>
public static class ResourceNames
{
    public const string Cardholder = "Cardholder";
    public const string Credential = "Credential";
    public const string Door = "Door";
    public const string Schedule = "Schedule";
    public const string AccessGroup = "AccessGroup";
}
