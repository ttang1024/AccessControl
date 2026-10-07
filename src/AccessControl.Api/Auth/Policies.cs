using Microsoft.AspNetCore.Authorization;

namespace AccessControl.Api.Auth;

/// <summary>
/// Authorization policies. Every endpoint names one; anything that does not is caught by the fallback
/// policy (authenticated callers only), so a forgotten annotation never makes a route public.
/// </summary>
public static class Policies
{
    /// <summary>Read cardholders, credentials, doors, schedules and groups.</summary>
    public const string Read = "Read";

    /// <summary>Manage cardholders, their credentials and group membership.</summary>
    public const string Enrol = "Enrol";

    /// <summary>Manage doors, schedules and access groups; release lockdowns.</summary>
    public const string Configure = "Configure";

    /// <summary>Put a door into lockdown. Wider than <see cref="Configure"/> because raising security is safe.</summary>
    public const string Lockdown = "Lockdown";

    /// <summary>Read the access-event trail (where people have been) and the change trail.</summary>
    public const string Audit = "Audit";

    public const string DoorController = "DoorController";

    public static IServiceCollection AddAccessControlAuthorization(this IServiceCollection services)
    {
        services.AddAuthorizationBuilder()
            .AddPolicy(Read, p => p.RequireRole(Roles.Admin, Roles.Operator, Roles.Auditor))
            .AddPolicy(Enrol, p => p.RequireRole(Roles.Admin, Roles.Operator))
            .AddPolicy(Configure, p => p.RequireRole(Roles.Admin))
            .AddPolicy(Lockdown, p => p.RequireRole(Roles.Admin, Roles.Operator))
            .AddPolicy(Audit, p => p.RequireRole(Roles.Admin, Roles.Auditor))
            .AddPolicy(DoorController, p => p.RequireRole(Roles.DoorController))
            .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());
        return services;
    }
}
