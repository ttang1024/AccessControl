using Microsoft.Extensions.Options;

namespace AccessControl.Api.Auth;

/// <summary>Fails startup on any key configuration that would weaken access control.</summary>
internal sealed class ApiKeyOptionsValidator(IHostEnvironment environment) : IValidateOptions<ApiKeyOptions>
{
    public ValidateOptionsResult Validate(string? name, ApiKeyOptions options)
    {
        var errors = new List<string>();
        var isDevelopment = environment.IsDevelopment();

        foreach (var (key, i) in options.ApiKeys.Select((k, i) => (k, i)))
        {
            var label = $"Auth:ApiKeys:{i} ({key.Name})";
            if (string.IsNullOrWhiteSpace(key.Name))
            {
                errors.Add($"Auth:ApiKeys:{i} needs a Name.");
            }

            if (!Roles.All.Contains(key.Role))
            {
                errors.Add($"{label}: Role must be one of {string.Join(", ", Roles.All)}.");
            }

            if (key.Sha256.Length != 64 || !key.Sha256.All(char.IsAsciiHexDigit))
            {
                errors.Add($"{label}: Sha256 must be 64 hex characters.");
            }
            else if (!isDevelopment && ApiKeyOptions.DevelopmentKeyHashes.Contains(key.Sha256))
            {
                errors.Add($"{label}: this is a published development key and is refused outside Development.");
            }

            if (key.Role == Roles.DoorController)
            {
                if (key.Doors.Count == 0)
                {
                    errors.Add($"{label}: a DoorController key must list the door ids it serves in Doors.");
                }

                foreach (var door in key.Doors)
                {
                    if (door == AccessControlClaims.AnyDoor)
                    {
                        if (!isDevelopment)
                        {
                            errors.Add($"{label}: Doors \"*\" is only allowed in Development; list the door ids.");
                        }
                    }
                    else if (!Guid.TryParse(door, out _))
                    {
                        errors.Add($"{label}: '{door}' in Doors is not a door id.");
                    }
                }
            }
            else if (key.Doors.Count > 0)
            {
                errors.Add($"{label}: Doors only applies to DoorController keys.");
            }
        }

        errors.AddRange(options.ApiKeys
            .GroupBy(k => k.Name, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => $"Auth:ApiKeys: Name '{g.Key}' is used more than once; names identify actors in the audit trail."));
        errors.AddRange(options.ApiKeys
            .GroupBy(k => k.Sha256, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => $"Auth:ApiKeys: {string.Join(", ", g.Select(k => k.Name))} share the same key."));

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
