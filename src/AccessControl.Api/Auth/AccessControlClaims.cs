using System.Globalization;
using System.Security.Claims;

namespace AccessControl.Api.Auth;

public static class AccessControlClaims
{
    /// <summary>A door a controller key may submit reads for (door id), or <see cref="AnyDoor"/>.</summary>
    public const string Door = "door";

    /// <summary>Development only: a controller key valid for every door.</summary>
    public const string AnyDoor = "*";

    public static bool MayUseDoor(this ClaimsPrincipal user, Guid doorId)
    {
        ArgumentNullException.ThrowIfNull(user);
        var id = doorId.ToString("D", CultureInfo.InvariantCulture);
        return user.HasClaim(c => c.Type == Door && (c.Value == AnyDoor || string.Equals(c.Value, id, StringComparison.OrdinalIgnoreCase)));
    }
}
