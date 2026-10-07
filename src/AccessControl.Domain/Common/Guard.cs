namespace AccessControl.Domain.Common;

internal static class Guard
{
    public static Guid NotEmpty(Guid value, string field)
    {
        if (value == Guid.Empty)
        {
            throw DomainException.Validation($"{field}.required", $"{field} must not be empty.");
        }

        return value;
    }

    /// <summary>Trims and validates a required human-readable name.</summary>
    public static string Name(string? value, string field, int maxLength = 100) =>
        Optional(value, field, maxLength)
        ?? throw DomainException.Validation($"{field}.required", $"{field} is required.");

    /// <summary>Trims an optional value; whitespace-only becomes <c>null</c>.</summary>
    public static string? Optional(string? value, string field, int maxLength = 100)
    {
        var trimmed = value?.Trim();
        if (string.IsNullOrEmpty(trimmed))
        {
            return null;
        }

        if (trimmed.Length > maxLength)
        {
            throw DomainException.Validation(
                $"{field}.too_long", $"{field} must be at most {maxLength} characters.");
        }

        return trimmed;
    }
}
