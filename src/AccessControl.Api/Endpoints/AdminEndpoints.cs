using AccessControl.Api.Auth;

namespace AccessControl.Api.Endpoints;

/// <summary>
/// Management API. Each resource is split into groups by policy (see <see cref="Policies"/>): add a route to
/// the group whose policy matches what it does, never directly to the resource group.
/// </summary>
internal static class AdminEndpoints
{
    public static RouteGroupBuilder MapAdminEndpoints(this RouteGroupBuilder api)
    {
        api.MapCardholderEndpoints();
        api.MapCredentialEndpoints();
        api.MapDoorEndpoints();
        api.MapScheduleEndpoints();
        api.MapAccessGroupEndpoints();
        return api;
    }
}
