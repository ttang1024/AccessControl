using AccessControl.Application.Abstractions;

namespace AccessControl.Infrastructure.Persistence;

/// <summary>Walks the hash chains of both audit logs.</summary>
internal sealed class AuditIntegrity(JsonLinesAccessEventLog accessEvents, JsonLinesChangeLog changes) : IAuditIntegrity
{
    public async Task<IReadOnlyList<AuditChainReport>> VerifyAsync(CancellationToken cancellationToken) =>
    [
        await accessEvents.Log.VerifyAsync(cancellationToken).ConfigureAwait(false),
        await changes.Log.VerifyAsync(cancellationToken).ConfigureAwait(false),
    ];
}
