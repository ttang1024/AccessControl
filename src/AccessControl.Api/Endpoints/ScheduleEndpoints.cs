using AccessControl.Api.Auth;
using AccessControl.Application.Schedules;

namespace AccessControl.Api.Endpoints;

internal static class ScheduleEndpoints
{
    public static void MapScheduleEndpoints(this RouteGroupBuilder api)
    {
        var g = api.MapGroup("/schedules").WithTags("Schedules");
        var read = g.WithPolicy(Policies.Read);
        var configure = g.WithPolicy(Policies.Configure);

        read.MapGet("/", (ScheduleService s, CancellationToken ct) => s.ListAsync(ct));
        configure.MapPost("/", (ScheduleRequest body, ScheduleService s, CancellationToken ct) =>
            s.CreateAsync(body, ct).CreatedAt("/api/v1/schedules", x => x.Id));
        read.MapGet("/{id:guid}", (Guid id, ScheduleService s, CancellationToken ct) => s.GetAsync(id, ct));
        configure.MapPut("/{id:guid}", (Guid id, ScheduleRequest body, ScheduleService s, CancellationToken ct) => s.UpdateAsync(id, body, ct));
        configure.MapDelete("/{id:guid}", (Guid id, ScheduleService s, CancellationToken ct) => s.DeleteAsync(id, ct).ThenNoContent());
    }
}
