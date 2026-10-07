using AccessControl.Application.Abstractions;

namespace AccessControl.Application.Audit;

/// <summary>Read side of the configuration-change trail, plus integrity checks over both audit logs.</summary>
public sealed class AuditService(IChangeAuditLog changes, IAuditIntegrity integrity)
{
    public Task<PagedResult<ChangeAuditEntry>> QueryChangesAsync(
        ChangeAuditFilter filter, PageRequest page, CancellationToken ct) =>
        changes.QueryAsync(filter, page, ct);

    public Task<IReadOnlyList<AuditChainReport>> VerifyAsync(CancellationToken ct) => integrity.VerifyAsync(ct);
}
