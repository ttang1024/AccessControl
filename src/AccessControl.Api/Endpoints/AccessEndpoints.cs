using System.Security.Claims;
using AccessControl.Api.Auth;
using AccessControl.Application.Abstractions;
using AccessControl.Application.Access;
using Microsoft.AspNetCore.Http.HttpResults;

namespace AccessControl.Api.Endpoints;

/// <summary>
/// What a door controller is told. Deliberately no denial reason: it would tell whoever holds a controller key
/// whether a card number is enrolled, and when it works. The reason is in the audit trail.
/// </summary>
internal sealed record AccessDecisionResponse(Guid EventId, bool Granted, DateTimeOffset EvaluatedAt);

internal static partial class AccessEndpoints
{
    public static RouteGroupBuilder MapAccessEndpoints(this RouteGroupBuilder api)
    {
        var access = api.MapGroup("/access").WithTags("Access");

        // Door controllers submit badge reads here. Any non-200 response must be treated as "deny".
        access.MapPost("/requests", RequestAccessAsync).RequireAuthorization(Policies.DoorController);

        access.MapGet("/events", (
                Guid? doorId,
                Guid? cardholderId,
                bool? granted,
                DateTimeOffset? from,
                DateTimeOffset? to,
                int? offset,
                int? limit,
                AccessService s,
                CancellationToken ct) =>
                s.QueryEventsAsync(
                    new AccessEventFilter(doorId, cardholderId, granted, from, to),
                    PageRequest.From(offset, limit),
                    ct))
            .RequireAuthorization(Policies.Audit);

        return api;
    }

    private static async Task<Results<Ok<AccessDecisionResponse>, ProblemHttpResult>> RequestAccessAsync(
        AccessRequest body, ClaimsPrincipal user, AccessService s, ILoggerFactory loggers, CancellationToken ct)
    {
        // Checked before the door is looked up, so a controller cannot discover which other doors exist.
        if (!user.MayUseDoor(body.DoorId))
        {
            Log.DoorNotAssigned(loggers.CreateLogger(typeof(AccessEndpoints)), user.ActorName() ?? "unknown", body.DoorId);
            return TypedResults.Problem(
                statusCode: StatusCodes.Status403Forbidden,
                title: "Forbidden",
                detail: "This controller is not assigned to the requested door.",
                extensions: new Dictionary<string, object?> { ["code"] = "door.not_assigned" });
        }

        var result = await s.RequestAccessAsync(body, ct);
        return TypedResults.Ok(new AccessDecisionResponse(result.EventId, result.Granted, result.EvaluatedAt));
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 4001, Level = LogLevel.Warning, Message = "Controller key {KeyName} submitted a read for door {DoorId}, which it is not assigned to")]
        public static partial void DoorNotAssigned(ILogger logger, string keyName, Guid doorId);
    }
}
