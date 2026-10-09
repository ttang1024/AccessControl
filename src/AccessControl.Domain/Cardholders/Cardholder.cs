using AccessControl.Domain.Common;

namespace AccessControl.Domain.Cardholders;

/// <summary>
/// A person who may be granted access. Access is never granted to a cardholder directly:
/// it comes from the access groups they belong to, and is gated by their enabled flag
/// and optional validity period.
/// </summary>
public sealed class Cardholder
{
    private readonly HashSet<Guid> _accessGroupIds;

    private Cardholder(
        Guid id,
        string firstName,
        string lastName,
        string? employeeNumber,
        bool isEnabled,
        DateTimeOffset? validFrom,
        DateTimeOffset? validUntil,
        IEnumerable<Guid> accessGroupIds)
    {
        Id = Guard.NotEmpty(id, "cardholder.id");
        FirstName = firstName;
        LastName = lastName;
        EmployeeNumber = employeeNumber;
        IsEnabled = isEnabled;
        ValidFrom = validFrom;
        ValidUntil = validUntil;
        _accessGroupIds = new HashSet<Guid>(accessGroupIds);
    }

    public Guid Id { get; }

    public string FirstName { get; private set; }

    public string LastName { get; private set; }

    public string? EmployeeNumber { get; private set; }

    public bool IsEnabled { get; private set; }

    /// <summary>Inclusive start of the validity period, or <c>null</c> for "since forever".</summary>
    public DateTimeOffset? ValidFrom { get; private set; }

    /// <summary>Exclusive end of the validity period, or <c>null</c> for "no end".</summary>
    public DateTimeOffset? ValidUntil { get; private set; }

    public IReadOnlyCollection<Guid> AccessGroupIds => _accessGroupIds;

    public static Cardholder Create(Guid id, string? firstName, string? lastName, string? employeeNumber = null) =>
        new(
            id,
            Guard.Name(firstName, "firstName"),
            Guard.Name(lastName, "lastName"),
            Guard.Optional(employeeNumber, "employeeNumber", 50),
            isEnabled: true,
            validFrom: null,
            validUntil: null,
            accessGroupIds: []);

    /// <summary>Rebuilds a cardholder from persisted state. Not for creating new cardholders.</summary>
    public static Cardholder Rehydrate(
        Guid id,
        string firstName,
        string lastName,
        string? employeeNumber,
        bool isEnabled,
        DateTimeOffset? validFrom,
        DateTimeOffset? validUntil,
        IEnumerable<Guid> accessGroupIds) =>
        new(id, firstName, lastName, employeeNumber, isEnabled, validFrom, validUntil, accessGroupIds);

    public void UpdateDetails(string? firstName, string? lastName, string? employeeNumber)
    {
        FirstName = Guard.Name(firstName, "firstName");
        LastName = Guard.Name(lastName, "lastName");
        EmployeeNumber = Guard.Optional(employeeNumber, "employeeNumber", 50);
    }

    public void SetValidityPeriod(DateTimeOffset? validFrom, DateTimeOffset? validUntil)
    {
        if (validFrom is not null && validUntil is not null && validFrom >= validUntil)
        {
            throw DomainException.Validation(
                "cardholder.invalid_validity_period", "validFrom must be earlier than validUntil.");
        }

        ValidFrom = validFrom;
        ValidUntil = validUntil;
    }

    public void Enable() => IsEnabled = true;

    public void Disable() => IsEnabled = false;

    public void JoinAccessGroup(Guid accessGroupId) =>
        _accessGroupIds.Add(Guard.NotEmpty(accessGroupId, "accessGroupId"));

    public void LeaveAccessGroup(Guid accessGroupId) => _accessGroupIds.Remove(accessGroupId);

    public bool IsWithinValidityPeriod(DateTimeOffset instant) =>
        (ValidFrom is null || instant >= ValidFrom) && (ValidUntil is null || instant < ValidUntil);
}
