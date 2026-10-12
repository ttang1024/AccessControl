using AccessControl.Api.Auth;
using AccessControl.Application.Abstractions;
using AccessControl.Application.Doors;
using Microsoft.AspNetCore.Mvc;

namespace AccessControl.Api.Endpoints;

internal static class DoorEndpoints
{
    public static void MapDoorEndpoints(this RouteGroupBuilder api)
    {
        var g = api.MapGroup("/doors").WithTags("Doors");
        var read = g.WithPolicy(Policies.Read);
        var configure = g.WithPolicy(Policies.Configure);
        var lockdown = g.WithPolicy(Policies.Lockdown);

        read.MapGet("/", (string? q, int? offset, int? limit, DoorService s, CancellationToken ct) =>
            s.SearchAsync(q, PageRequest.From(offset, limit), ct));
        configure.MapPost("/", (DoorRequest body, DoorService s, CancellationToken ct) =>
            s.CreateAsync(body, ct).CreatedAt("/api/v1/doors", d => d.Id));
        read.MapGet("/{id:guid}", (Guid id, DoorService s, CancellationToken ct) => s.GetAsync(id, ct));
        configure.MapPut("/{id:guid}", (Guid id, DoorRequest body, [FromHeader(Name = ETags.IfMatchHeader)] string? ifMatch, DoorService s, CancellationToken ct) =>
            s.UpdateAsync(id, body, ETags.ParseIfMatch(ifMatch), ct));
        configure.MapDelete("/{id:guid}", (Guid id, [FromHeader(Name = ETags.IfMatchHeader)] string? ifMatch, DoorService s, CancellationToken ct) =>
            s.DeleteAsync(id, ETags.ParseIfMatch(ifMatch), ct).ThenNoContent());
        lockdown.MapPost("/{id:guid}/lockdown", (Guid id, [FromHeader(Name = ETags.IfMatchHeader)] string? ifMatch, DoorService s, CancellationToken ct) =>
            s.LockdownAsync(id, ETags.ParseIfMatch(ifMatch), ct));
        configure.MapPost("/{id:guid}/release", (Guid id, [FromHeader(Name = ETags.IfMatchHeader)] string? ifMatch, DoorService s, CancellationToken ct) =>
            s.ReleaseLockdownAsync(id, ETags.ParseIfMatch(ifMatch), ct));

        // Site-wide, one atomic commit each. Same policies as the per-door operations.
        lockdown.MapPost("/lockdown", (DoorService s, CancellationToken ct) => s.LockdownSiteAsync(ct));
        configure.MapPost("/release", (DoorService s, CancellationToken ct) => s.ReleaseSiteAsync(ct));
    }
}
