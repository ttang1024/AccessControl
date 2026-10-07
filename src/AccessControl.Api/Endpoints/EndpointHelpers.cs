using Microsoft.AspNetCore.Http.HttpResults;

namespace AccessControl.Api.Endpoints;

internal static class EndpointHelpers
{
    /// <summary>A sub-group of <paramref name="group"/> whose routes all require <paramref name="policy"/>.</summary>
    public static RouteGroupBuilder WithPolicy(this RouteGroupBuilder group, string policy) =>
        group.MapGroup(string.Empty).RequireAuthorization(policy);

    /// <summary>201 with a <c>Location</c> of <c>{collectionPath}/{id}</c>.</summary>
    public static async Task<Created<T>> CreatedAt<T>(this Task<T> creating, string collectionPath, Func<T, Guid> id)
    {
        var created = await creating.ConfigureAwait(false);
        return TypedResults.Created($"{collectionPath}/{id(created)}", created);
    }

    public static async Task<NoContent> ThenNoContent(this Task operation)
    {
        await operation.ConfigureAwait(false);
        return TypedResults.NoContent();
    }
}
