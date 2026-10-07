using System.Security.Claims;
using AccessControl.Application.Abstractions;

namespace AccessControl.Api.Auth;

/// <summary>The authenticated API key's name, recorded as the actor of every committed change.</summary>
internal sealed class HttpActorContext(IHttpContextAccessor accessor) : IActorContext
{
    public string Actor =>
        accessor.HttpContext?.User.FindFirstValue(ClaimTypes.Name) is { Length: > 0 } name ? name : "anonymous";
}
