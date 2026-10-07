using AccessControl.Api.Auth;
using AccessControl.Application.Abstractions;
using AccessControl.Application.Audit;

namespace AccessControl.Api.Endpoints;

internal static class AuditEndpoints
{
    public static RouteGroupBuilder MapAuditEndpoints(this RouteGroupBuilder api)
    {
        var audit = api.MapGroup("/audit").WithTags("Audit").RequireAuthorization(Policies.Audit);

        // Who changed what configuration, when; newest first.
        audit.MapGet("/changes", (
                string? entityType,
                Guid? entityId,
                string? actor,
                DateTimeOffset? from,
                DateTimeOffset? to,
                int? offset,
                int? limit,
                AuditService s,
                CancellationToken ct) =>
            s.QueryChangesAsync(
                new ChangeAuditFilter(entityType, entityId, actor, from, to),
                PageRequest.From(offset, limit),
                ct));

        // Walks the hash chains of both audit logs. Scans every file: run it from monitoring, not per request.
        audit.MapGet("/verify", (AuditService s, CancellationToken ct) => s.VerifyAsync(ct));

        return api;
    }
}
