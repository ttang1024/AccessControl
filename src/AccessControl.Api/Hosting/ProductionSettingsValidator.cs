using AccessControl.Infrastructure.Storage;
using Microsoft.AspNetCore.HostFiltering;
using Microsoft.Extensions.Options;

namespace AccessControl.Api.Hosting;

/// <summary>
/// Fails startup outside Development when a setting the deployment checklist requires is missing, instead of
/// silently running with a weaker default.
/// </summary>
internal sealed class ProductionSettingsValidator(IHostEnvironment environment)
    : IValidateOptions<StorageOptions>, IValidateOptions<HostFilteringOptions>
{
    /// <summary>Shorter keys are guessable enough to let someone with file access re-sign a forged audit chain.</summary>
    public const int MinimumAuditHmacKeyLength = 32;

    public ValidateOptionsResult Validate(string? name, StorageOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (environment.IsDevelopment() || options.AuditHmacKey?.Length >= MinimumAuditHmacKeyLength)
        {
            return ValidateOptionsResult.Success;
        }

        return ValidateOptionsResult.Fail(
            $"Storage:AuditHmacKey must be set (at least {MinimumAuditHmacKeyLength} characters, from a secret store) " +
            "outside Development; without it anyone with file access can rewrite the audit trail undetected.");
    }

    public ValidateOptionsResult Validate(string? name, HostFilteringOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (environment.IsDevelopment() || (options.AllowedHosts.Count > 0 && !options.AllowedHosts.Contains("*")))
        {
            return ValidateOptionsResult.Success;
        }

        return ValidateOptionsResult.Fail("AllowedHosts must list the real host name(s) outside Development, not \"*\".");
    }
}
