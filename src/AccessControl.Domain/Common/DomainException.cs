namespace AccessControl.Domain.Common;

/// <summary>How a domain rule was broken. Drives the HTTP status the API returns.</summary>
public enum DomainErrorKind
{
    /// <summary>The input itself is malformed or out of range.</summary>
    Validation,

    /// <summary>The input is well formed but the aggregate is in a state that forbids the operation.</summary>
    InvalidState,
}

/// <summary>Raised when an aggregate rejects an operation. Never used for infrastructure failures.</summary>
public sealed class DomainException : Exception
{
    public DomainException(DomainErrorKind kind, string code, string message)
        : base(message)
    {
        Kind = kind;
        Code = code;
    }

    public DomainErrorKind Kind { get; }

    /// <summary>Stable, machine-readable error code (e.g. <c>credential.invalid_transition</c>).</summary>
    public string Code { get; }

    public static DomainException Validation(string code, string message) =>
        new(DomainErrorKind.Validation, code, message);

    public static DomainException InvalidState(string code, string message) =>
        new(DomainErrorKind.InvalidState, code, message);
}
