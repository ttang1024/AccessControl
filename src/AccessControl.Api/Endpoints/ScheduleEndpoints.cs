using AccessControl.Api.Auth;
using AccessControl.Application.Abstractions;
using AccessControl.Application.Schedules;
using Microsoft.AspNetCore.Mvc;

namespace AccessControl.Api.Endpoints;

internal static class ScheduleEndpoints
{
    public static void MapScheduleEndpoints(this RouteGroupBuilder api)
    {
        var g = api.MapGroup("/schedules").WithTags("Schedules");
        var read = g.WithPolicy(Policies.Read);
        var configure = g.WithPolicy(Policies.Configure);

        read.MapGet("/", (string? q, int? offset, int? limit, ScheduleService s, CancellationToken ct) =>
            s.SearchAsync(q, PageRequest.From(offset, limit), ct));
        configure.MapPost("/", (ScheduleRequest body, ScheduleService s, CancellationToken ct) =>
            s.CreateAsync(body, ct).CreatedAt("/api/v1/schedules", x => x.Id));
        read.MapGet("/{id:guid}", (Guid id, ScheduleService s, CancellationToken ct) => s.GetAsync(id, ct));
        configure.MapPut("/{id:guid}", (Guid id, ScheduleRequest body, [FromHeader(Name = ETags.IfMatchHeader)] string? ifMatch, ScheduleService s, CancellationToken ct) =>
            s.UpdateAsync(id, body, ETags.ParseIfMatch(ifMatch), ct));
        configure.MapDelete("/{id:guid}", (Guid id, [FromHeader(Name = ETags.IfMatchHeader)] string? ifMatch, ScheduleService s, CancellationToken ct) =>
            s.DeleteAsync(id, ETags.ParseIfMatch(ifMatch), ct).ThenNoContent());
    }
}
