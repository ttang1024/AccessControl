using AccessControl.Api.Auth;
using AccessControl.Application.Abstractions;
using AccessControl.Application.Cardholders;
using AccessControl.Application.Credentials;
using Microsoft.AspNetCore.Mvc;

namespace AccessControl.Api.Endpoints;

internal static class CardholderEndpoints
{
    public static void MapCardholderEndpoints(this RouteGroupBuilder api)
    {
        var g = api.MapGroup("/cardholders").WithTags("Cardholders");
        var read = g.WithPolicy(Policies.Read);
        var enrol = g.WithPolicy(Policies.Enrol);

        read.MapGet("/", (string? q, Guid? accessGroupId, int? offset, int? limit, CardholderService s, CancellationToken ct) =>
            s.SearchAsync(q, accessGroupId, PageRequest.From(offset, limit), ct));
        enrol.MapPost("/", (CardholderRequest body, CardholderService s, CancellationToken ct) =>
            s.CreateAsync(body, ct).CreatedAt("/api/v1/cardholders", c => c.Id));
        read.MapGet("/{id:guid}", (Guid id, CardholderService s, CancellationToken ct) => s.GetAsync(id, ct));
        enrol.MapPut("/{id:guid}", (Guid id, CardholderRequest body, [FromHeader(Name = ETags.IfMatchHeader)] string? ifMatch, CardholderService s, CancellationToken ct) =>
            s.UpdateAsync(id, body, ETags.ParseIfMatch(ifMatch), ct));
        enrol.MapPost("/{id:guid}/enable", (Guid id, [FromHeader(Name = ETags.IfMatchHeader)] string? ifMatch, CardholderService s, CancellationToken ct) =>
            s.EnableAsync(id, ETags.ParseIfMatch(ifMatch), ct));
        enrol.MapPost("/{id:guid}/disable", (Guid id, [FromHeader(Name = ETags.IfMatchHeader)] string? ifMatch, CardholderService s, CancellationToken ct) =>
            s.DisableAsync(id, ETags.ParseIfMatch(ifMatch), ct));

        enrol.MapPut("/{id:guid}/access-groups/{groupId:guid}", (Guid id, Guid groupId, [FromHeader(Name = ETags.IfMatchHeader)] string? ifMatch, CardholderService s, CancellationToken ct) =>
            s.JoinAccessGroupAsync(id, groupId, ETags.ParseIfMatch(ifMatch), ct));
        enrol.MapDelete("/{id:guid}/access-groups/{groupId:guid}", (Guid id, Guid groupId, [FromHeader(Name = ETags.IfMatchHeader)] string? ifMatch, CardholderService s, CancellationToken ct) =>
            s.LeaveAccessGroupAsync(id, groupId, ETags.ParseIfMatch(ifMatch), ct));

        read.MapGet("/{id:guid}/credentials", (Guid id, CredentialService s, CancellationToken ct) =>
            s.ListForCardholderAsync(id, ct));
        enrol.MapPost("/{id:guid}/credentials", (Guid id, IssueCredentialRequest body, CredentialService s, CancellationToken ct) =>
            s.IssueAsync(id, body, ct).CreatedAt("/api/v1/credentials", c => c.Id));
    }
}
