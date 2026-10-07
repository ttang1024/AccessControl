using AccessControl.Api.Auth;
using AccessControl.Application.AccessGroups;

namespace AccessControl.Api.Endpoints;

internal static class AccessGroupEndpoints
{
    public static void MapAccessGroupEndpoints(this RouteGroupBuilder api)
    {
        var g = api.MapGroup("/access-groups").WithTags("Access groups");
        var read = g.WithPolicy(Policies.Read);
        var configure = g.WithPolicy(Policies.Configure);

        read.MapGet("/", (AccessGroupService s, CancellationToken ct) => s.ListAsync(ct));
        configure.MapPost("/", (AccessGroupRequest body, AccessGroupService s, CancellationToken ct) =>
            s.CreateAsync(body, ct).CreatedAt("/api/v1/access-groups", x => x.Id));
        read.MapGet("/{id:guid}", (Guid id, AccessGroupService s, CancellationToken ct) => s.GetAsync(id, ct));
        configure.MapPut("/{id:guid}", (Guid id, AccessGroupRequest body, AccessGroupService s, CancellationToken ct) =>
            s.UpdateAsync(id, body, ct));
        configure.MapDelete("/{id:guid}", (Guid id, AccessGroupService s, CancellationToken ct) => s.DeleteAsync(id, ct).ThenNoContent());
        read.MapGet("/{id:guid}/members", (Guid id, AccessGroupService s, CancellationToken ct) => s.ListMembersAsync(id, ct));
        configure.MapPut("/{id:guid}/doors/{doorId:guid}", (Guid id, Guid doorId, AccessGroupService s, CancellationToken ct) =>
            s.AddDoorAsync(id, doorId, ct));
        configure.MapDelete("/{id:guid}/doors/{doorId:guid}", (Guid id, Guid doorId, AccessGroupService s, CancellationToken ct) =>
            s.RemoveDoorAsync(id, doorId, ct));
    }
}
