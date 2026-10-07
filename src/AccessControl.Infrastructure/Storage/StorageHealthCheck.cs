using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace AccessControl.Infrastructure.Storage;

/// <summary>
/// Unhealthy if the data directory is not writable or free space is below <c>Storage:MinimumFreeDiskBytes</c>:
/// once the disk is full every audit append fails, and every badge read is denied.
/// </summary>
internal sealed class StorageHealthCheck(DocumentStore store, IOptions<StorageOptions> options) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var directory = Path.GetDirectoryName(store.FilePath)!;
        var probe = Path.Combine(directory, $".health-{Guid.NewGuid():N}");
        try
        {
            File.WriteAllText(probe, string.Empty);
            File.Delete(probe);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("Data directory is not writable.", ex));
        }

        var free = new DriveInfo(directory).AvailableFreeSpace;
        return Task.FromResult(free < options.Value.MinimumFreeDiskBytes
            ? HealthCheckResult.Unhealthy("Data volume is nearly full.", data: new Dictionary<string, object> { ["freeBytes"] = free })
            : HealthCheckResult.Healthy());
    }
}
