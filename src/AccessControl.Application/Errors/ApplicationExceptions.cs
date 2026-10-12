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

    /// <summary>Deliberately does not repeat the card number: responses never carry one (and errors get logged).</summary>
    public static ConflictException DuplicateCardNumber() =>
        new("credential.duplicate_card_number", "This card number is already enrolled. Card numbers are unique for life, even after a card is revoked.");

    /// <summary>A door or schedule cannot be deleted while access groups reference it.</summary>
    public static ConflictException InUseByGroups(string resource, IReadOnlyCollection<string> groupNames) =>
        new(
            $"{resource.ToLowerInvariant()}.in_use",
            $"{resource} is used by {groupNames.Count} access group(s): {string.Join(", ", groupNames)}. Remove it from them first.");
}

/// <summary>
/// The client's copy is out of date: it sent the version it last saw (HTTP <c>If-Match</c>) and the resource has
/// changed since. Maps to HTTP 412. Nothing was persisted; the client must reload before retrying.
/// </summary>
public sealed class PreconditionFailedException(string resource, Guid id, int expected, int actual)
    : Exception($"{resource} '{id}' is at version {actual}, not {expected}. Reload it and reapply the change.")
{
    public string Code { get; } = "precondition_failed";
}

/// <summary>The caller is authenticated but may not perform this particular change. Maps to HTTP 403.</summary>
public sealed class ForbiddenException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}
