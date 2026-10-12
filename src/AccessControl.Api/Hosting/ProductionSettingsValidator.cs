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
    /// <summary>Shorter keys are guessable enough to re-sign a forged audit chain or reverse card fingerprints.</summary>
    public const int MinimumAuditHmacKeyLength = 32;

    public ValidateOptionsResult Validate(string? name, StorageOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (environment.IsDevelopment())
        {
            return ValidateOptionsResult.Success;
        }

        var errors = new List<string>();
        if (!(options.AuditHmacKey?.Length >= MinimumAuditHmacKeyLength))
        {
            errors.Add(
                $"Storage:AuditHmacKey must be set (at least {MinimumAuditHmacKeyLength} characters, from a secret store) " +
                "outside Development; without it anyone with file access can rewrite the audit trail undetected.");
        }

        if (!(options.CardNumberKey?.Length >= MinimumAuditHmacKeyLength))
        {
            errors.Add(
                $"Storage:CardNumberKey must be set (at least {MinimumAuditHmacKeyLength} characters, from a secret store) " +
                "outside Development; without it the stored card fingerprints of short card formats can be reversed by trying every number.");
        }

        if (options.CardNumberKey is not null && options.CardNumberKey == options.AuditHmacKey)
        {
            errors.Add("Storage:CardNumberKey and Storage:AuditHmacKey must be different secrets.");
        }

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
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
