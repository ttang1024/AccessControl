using AccessControl.Application.Abstractions;

namespace AccessControl.Api.Auth;

/// <summary>The authenticated caller, recorded as the actor of every committed change.</summary>
internal sealed class HttpActorContext(IHttpContextAccessor accessor) : IActorContext
{
    public string Actor => accessor.HttpContext?.User.ActorName() ?? "anonymous";

    public bool CanGrantRestrictedAccess => accessor.HttpContext?.User.IsInRole(Roles.Admin) == true;
}
