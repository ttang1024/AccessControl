namespace AccessControl.Application.Errors;

/// <summary>
/// The request itself is malformed (e.g. paging out of range), as opposed to breaking a domain rule
/// (<c>DomainException</c>). Maps to HTTP 400.
/// </summary>
public sealed class RequestValidationException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

/// <summary>A referenced resource does not exist. Maps to HTTP 404.</summary>
public sealed class NotFoundException(string resource, Guid id)
    : Exception($"{resource} '{id}' was not found.")
{
    public string Code { get; } = $"{resource.ToLowerInvariant()}.not_found";
}

/// <summary>
/// The operation conflicts with current state: a uniqueness rule, a reference that blocks deletion,
/// or a concurrent modification. Maps to HTTP 409. Nothing was persisted.
/// </summary>
public sealed class ConflictException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;

    public static ConflictException Concurrency() =>
        new("concurrency_conflict", "The resource was changed by another request. Reload and retry.");

    public static ConflictException DuplicateCardNumber(string cardNumber) =>
        new("credential.duplicate_card_number", $"Card number {cardNumber} is already enrolled.");

    /// <summary>A door or schedule cannot be deleted while access groups reference it.</summary>
    public static ConflictException InUseByGroups(string resource, IReadOnlyCollection<string> groupNames) =>
        new(
            $"{resource.ToLowerInvariant()}.in_use",
            $"{resource} is used by {groupNames.Count} access group(s): {string.Join(", ", groupNames)}. Remove it from them first.");
}
