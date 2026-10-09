using AccessControl.Application.Abstractions;
using AccessControl.Application.Credentials;

namespace AccessControl.Application.Audit;

/// <summary>Read side of the configuration-change trail, plus integrity checks over both audit logs.</summary>
public sealed class AuditService(IChangeAuditLog changes, IAuditIntegrity integrity, AuditQueryWindow window)
{
    /// <summary>Card numbers in the before/after documents are masked (see <see cref="CardNumberMask"/>).</summary>
    public async Task<PagedResult<ChangeAuditEntry>> QueryChangesAsync(
        ChangeAuditFilter filter, PageRequest page, CancellationToken ct) =>
        (await changes
            .QueryAsync(filter with { From = window.StartOf(filter.From, filter.To) }, page.EnsureAuditDepth(), ct)
            .ConfigureAwait(false))
        .Map(e => e with { Before = CardNumberMask.MaskDocument(e.Before), After = CardNumberMask.MaskDocument(e.After) });

    public Task<IReadOnlyList<AuditChainReport>> VerifyAsync(CancellationToken ct) => integrity.VerifyAsync(ct);
}
