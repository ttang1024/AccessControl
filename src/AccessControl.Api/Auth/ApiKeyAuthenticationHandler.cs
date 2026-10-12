using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace AccessControl.Api.Auth;

/// <summary>
/// Authenticates requests carrying <c>X-Api-Key</c> by comparing its SHA-256 against configured hashes
/// in constant time. Requests without the header are anonymous and fail authorization on protected routes.
/// </summary>
public sealed partial class ApiKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IOptions<ApiKeyOptions> keys)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "ApiKey";
    public const string HeaderName = "X-Api-Key";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(HeaderName, out var values) || values.Count != 1 || string.IsNullOrEmpty(values[0]))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        // Read once at startup (validated by ApiKeyOptionsValidator); rotate keys by restarting.
        var settings = keys.Value;
        if (settings.RequireHttps && !Request.IsHttps)
        {
            // The key has already crossed the network in the clear; refuse it so the mistake is noticed.
            Log.KeyOverPlainHttp(Logger, Context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            return Task.FromResult(AuthenticateResult.Fail("API keys are only accepted over HTTPS."));
        }

        var presented = SHA256.HashData(Encoding.UTF8.GetBytes(values[0]!));
        ApiKeyEntry? match = null;
        foreach (var entry in settings.ApiKeys)
        {
            // Compare against every key without early exit so timing does not reveal which entry matched.
            if (CryptographicOperations.FixedTimeEquals(presented, Convert.FromHexString(entry.Sha256)))
            {
                match = entry;
            }
        }

        if (match is null)
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid API key."));
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, match.Name),
            new(ClaimTypes.Role, match.Role),
        };
        if (match.Role == Roles.DoorController)
        {
            claims.AddRange(match.Doors.Select(d => new Claim(AccessControlClaims.Door, d)));
        }

        var identity = new ClaimsIdentity(claims, SchemeName);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 4000, Level = LogLevel.Warning, Message = "Rejected an API key sent over plain HTTP from {RemoteIp}; the key should be considered exposed")]
        public static partial void KeyOverPlainHttp(ILogger logger, string remoteIp);
    }
}
