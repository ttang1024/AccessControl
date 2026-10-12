using AccessControl.Application.Abstractions;

namespace AccessControl.Application.Audit;

/// <summary>Read side of the configuration-change trail, plus integrity checks over both audit logs.</summary>
public sealed class AuditService(IChangeAuditLog changes, IAuditIntegrity integrity, AuditQueryWindow window)
{
    /// <summary>Before/after documents hold card fingerprints, never card numbers, so they are returned as stored.</summary>
    public Task<PagedResult<ChangeAuditEntry>> QueryChangesAsync(
        ChangeAuditFilter filter, PageRequest page, CancellationToken ct) =>
        changes.QueryAsync(filter with { From = window.StartOf(filter.From, filter.To) }, page.EnsureAuditDepth(), ct);

    public Task<IReadOnlyList<AuditChainReport>> VerifyAsync(CancellationToken ct) => integrity.VerifyAsync(ct);
}
