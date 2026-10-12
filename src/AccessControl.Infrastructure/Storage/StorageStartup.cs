using AccessControl.Infrastructure.Persistence;
using Microsoft.Extensions.Hosting;

namespace AccessControl.Infrastructure.Storage;

/// <summary>
/// Opens storage when the host starts rather than on the first request: takes the data-directory lock, loads and
/// replays the store and repairs the audit logs, so a second instance, a corrupt store or a broken change log stops
/// startup (and fails the deployment) instead of failing the first badge read.
/// </summary>
internal sealed class StorageStartup(DocumentStore store, JsonLinesAccessEventLog accessEvents) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        GC.KeepAlive(store);
        GC.KeepAlive(accessEvents);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
