using System.Net;
using System.Net.Sockets;
using System.Threading.RateLimiting;
using AccessControl.Api.Auth;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AccessControl.Api.RateLimiting;

public sealed class RateLimitingOptions
{
    public const string SectionName = "RateLimiting";

    /// <summary>
    /// Badge reads per minute per controller key. Slows card-number enumeration with a stolen key; set it
    /// above the busiest door's real peak, because a throttled read is a denied entry.
    /// </summary>
    public int DoorControllerPermitsPerMinute { get; set; } = 120;

    /// <summary>Requests per minute per Admin/Operator/Auditor key.</summary>
    public int UserPermitsPerMinute { get; set; } = 600;

    /// <summary>
    /// Requests per minute per client IP for unauthenticated traffic, including wrong keys. Slows API key guessing.
    /// <c>/health</c> has a separate budget of the same size, so that bad-key traffic from the same address (e.g. a
    /// load balancer or proxy) cannot make liveness probes fail and get a healthy instance restarted.
    /// </summary>
    public int AnonymousPermitsPerMinute { get; set; } = 60;
}

internal static class RateLimitingSetup
{
    public const string HealthPath = "/health";

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
                // Runs after authentication, so a valid caller gets its own budget and everything else is per client network.
                var user = context.User;
                var client = ClientPartition(context.Connection.RemoteIpAddress);
                var (key, permits) = context.Request.Path.StartsWithSegments(HealthPath)
                    ? ("health:" + client, settings.AnonymousPermitsPerMinute)
                    : user.ActorName() is { } actor
                        ? ("actor:" + actor,
                            user.IsInRole(Roles.DoorController) ? settings.DoorControllerPermitsPerMinute : settings.UserPermitsPerMinute)
                        : ("ip:" + client, settings.AnonymousPermitsPerMinute);

                // Sliding window (six 10-second segments): a fixed window lets twice the limit through across a boundary.
                return RateLimitPartition.GetSlidingWindowLimiter(key, _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = permits,
                    Window = TimeSpan.FromMinutes(1),
                    SegmentsPerWindow = 6,
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

    /// <summary>
    /// The rate-limit partition for a client address. IPv6 clients usually control a whole /64 and can rotate through
    /// it at will, so they are grouped by /64; IPv4-mapped addresses count as their IPv4 address.
    /// </summary>
    public static string ClientPartition(IPAddress? address)
    {
        if (address is null)
        {
            return "unknown";
        }

        if (address.IsIPv4MappedToIPv6)
        {
            return address.MapToIPv4().ToString();
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return address.ToString();
        }

        var bytes = address.GetAddressBytes();
        Array.Clear(bytes, 8, 8);
        return new IPAddress(bytes) + "/64";
    }
}
