using AccessControl.Api.Auth;
using AccessControl.Application.Doors;

namespace AccessControl.Api.Endpoints;

internal static class DoorEndpoints
{
    public static void MapDoorEndpoints(this RouteGroupBuilder api)
    {
        var g = api.MapGroup("/doors").WithTags("Doors");
        var read = g.WithPolicy(Policies.Read);
        var configure = g.WithPolicy(Policies.Configure);
        var lockdown = g.WithPolicy(Policies.Lockdown);

        read.MapGet("/", (DoorService s, CancellationToken ct) => s.ListAsync(ct));
        configure.MapPost("/", (DoorRequest body, DoorService s, CancellationToken ct) =>
            s.CreateAsync(body, ct).CreatedAt("/api/v1/doors", d => d.Id));
        read.MapGet("/{id:guid}", (Guid id, DoorService s, CancellationToken ct) => s.GetAsync(id, ct));
        configure.MapPut("/{id:guid}", (Guid id, DoorRequest body, DoorService s, CancellationToken ct) => s.UpdateAsync(id, body, ct));
        configure.MapDelete("/{id:guid}", (Guid id, DoorService s, CancellationToken ct) => s.DeleteAsync(id, ct).ThenNoContent());
        lockdown.MapPost("/{id:guid}/lockdown", (Guid id, DoorService s, CancellationToken ct) => s.LockdownAsync(id, ct));
        configure.MapPost("/{id:guid}/release", (Guid id, DoorService s, CancellationToken ct) => s.ReleaseLockdownAsync(id, ct));
    }
}
