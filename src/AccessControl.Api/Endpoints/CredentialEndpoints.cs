using AccessControl.Api.Auth;
using AccessControl.Application.Credentials;

namespace AccessControl.Api.Endpoints;

/// <summary>Credentials are issued under their cardholder (see <see cref="CardholderEndpoints"/>).</summary>
internal static class CredentialEndpoints
{
    public static void MapCredentialEndpoints(this RouteGroupBuilder api)
    {
        var g = api.MapGroup("/credentials").WithTags("Credentials");
        var read = g.WithPolicy(Policies.Read);
        var enrol = g.WithPolicy(Policies.Enrol);

        read.MapGet("/{id:guid}", (Guid id, CredentialService s, CancellationToken ct) => s.GetAsync(id, ct));
        enrol.MapPut("/{id:guid}/expiry", (Guid id, ChangeCredentialExpiryRequest body, CredentialService s, CancellationToken ct) =>
            s.ChangeExpiryAsync(id, body, ct));
        enrol.MapPost("/{id:guid}/suspend", (Guid id, CredentialService s, CancellationToken ct) => s.SuspendAsync(id, ct));
        enrol.MapPost("/{id:guid}/reinstate", (Guid id, CredentialService s, CancellationToken ct) => s.ReinstateAsync(id, ct));
        enrol.MapPost("/{id:guid}/report-lost", (Guid id, CredentialService s, CancellationToken ct) => s.ReportLostAsync(id, ct));
        enrol.MapPost("/{id:guid}/revoke", (Guid id, CredentialService s, CancellationToken ct) => s.RevokeAsync(id, ct));
    }
}
