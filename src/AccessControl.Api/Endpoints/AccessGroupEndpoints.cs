using AccessControl.Api.Auth;
using AccessControl.Application.Abstractions;
using AccessControl.Application.AccessGroups;
using Microsoft.AspNetCore.Mvc;

namespace AccessControl.Api.Endpoints;

internal static class AccessGroupEndpoints
{
    public static void MapAccessGroupEndpoints(this RouteGroupBuilder api)
    {
        var g = api.MapGroup("/access-groups").WithTags("Access groups");
        var read = g.WithPolicy(Policies.Read);
        var configure = g.WithPolicy(Policies.Configure);

        read.MapGet("/", (string? q, int? offset, int? limit, AccessGroupService s, CancellationToken ct) =>
            s.SearchAsync(q, PageRequest.From(offset, limit), ct));
        configure.MapPost("/", (AccessGroupRequest body, AccessGroupService s, CancellationToken ct) =>
            s.CreateAsync(body, ct).CreatedAt("/api/v1/access-groups", x => x.Id));
        read.MapGet("/{id:guid}", (Guid id, AccessGroupService s, CancellationToken ct) => s.GetAsync(id, ct));
        configure.MapPut("/{id:guid}", (Guid id, AccessGroupRequest body, [FromHeader(Name = ETags.IfMatchHeader)] string? ifMatch, AccessGroupService s, CancellationToken ct) =>
            s.UpdateAsync(id, body, ETags.ParseIfMatch(ifMatch), ct));
        configure.MapDelete("/{id:guid}", (Guid id, [FromHeader(Name = ETags.IfMatchHeader)] string? ifMatch, AccessGroupService s, CancellationToken ct) =>
            s.DeleteAsync(id, ETags.ParseIfMatch(ifMatch), ct).ThenNoContent());
        read.MapGet("/{id:guid}/members", (Guid id, int? offset, int? limit, AccessGroupService s, CancellationToken ct) =>
            s.ListMembersAsync(id, PageRequest.From(offset, limit), ct));
        configure.MapPut("/{id:guid}/doors/{doorId:guid}", (Guid id, Guid doorId, [FromHeader(Name = ETags.IfMatchHeader)] string? ifMatch, AccessGroupService s, CancellationToken ct) =>
            s.AddDoorAsync(id, doorId, ETags.ParseIfMatch(ifMatch), ct));
        configure.MapDelete("/{id:guid}/doors/{doorId:guid}", (Guid id, Guid doorId, [FromHeader(Name = ETags.IfMatchHeader)] string? ifMatch, AccessGroupService s, CancellationToken ct) =>
            s.RemoveDoorAsync(id, doorId, ETags.ParseIfMatch(ifMatch), ct));
    }
}
