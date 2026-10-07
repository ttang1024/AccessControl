using System.Security.Claims;
using System.Threading.RateLimiting;
using AccessControl.Api.Auth;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AccessControl.Api.RateLimiting;

public sealed class RateLimitingOptions
{
    public const string SectionName = "RateLimiting";

    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Badge reads per minute per controller key. Slows card-number enumeration with a stolen key; set it
    /// above the busiest door's real peak, because a throttled read is a denied entry.
    /// </summary>
    public int DoorControllerPermitsPerMinute { get; set; } = 120;

    /// <summary>Requests per minute per Admin/Operator/Auditor key.</summary>
    public int UserPermitsPerMinute { get; set; } = 600;

    /// <summary>
    /// Requests per minute per client IP for unauthenticated traffic, including wrong keys and <c>/health</c>.
    /// Slows API key guessing.
    /// </summary>
    public int AnonymousPermitsPerMinute { get; set; } = 60;
}

internal static class RateLimitingSetup
{
    public static IServiceCollection AddAccessControlRateLimiting(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<RateLimitingOptions>()
            .Bind(configuration.GetSection(RateLimitingOptions.SectionName))
            .Validate(
                o => o.DoorControllerPermitsPerMinute > 0 && o.UserPermitsPerMinute > 0 && o.AnonymousPermitsPerMinute > 0,
                "RateLimiting permits must be positive.")
            .ValidateOnStart();

        services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
            {
                var settings = context.RequestServices.GetRequiredService<IOptions<RateLimitingOptions>>().Value;
                if (!settings.Enabled)
                {
                    return RateLimitPartition.GetNoLimiter("disabled");
                }

                // Runs after authentication, so a valid key gets its own budget and everything else is per IP.
                var user = context.User;
                var (key, permits) = user.Identity?.IsAuthenticated == true
                    ? ("key:" + user.FindFirstValue(ClaimTypes.Name),
                        user.IsInRole(Roles.DoorController) ? settings.DoorControllerPermitsPerMinute : settings.UserPermitsPerMinute)
                    : ("ip:" + (context.Connection.RemoteIpAddress?.ToString() ?? "unknown"), settings.AnonymousPermitsPerMinute);

                return RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = permits,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0,
                });
            });
            o.OnRejected = async (context, ct) =>
            {
                if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                {
                    context.HttpContext.Response.Headers.RetryAfter = ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(System.Globalization.CultureInfo.InvariantCulture);
                }

                await context.HttpContext.RequestServices.GetRequiredService<IProblemDetailsService>().TryWriteAsync(new ProblemDetailsContext
                {
                    HttpContext = context.HttpContext,
                    ProblemDetails = new ProblemDetails
                    {
                        Status = StatusCodes.Status429TooManyRequests,
                        Title = "Too many requests",
                        Extensions = { ["code"] = "rate_limited" },
                    },
                }).ConfigureAwait(false);
            };
        });
        return services;
    }
}
