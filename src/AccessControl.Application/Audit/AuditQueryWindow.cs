using Microsoft.Extensions.Options;

namespace AccessControl.Application.Audit;

public sealed class AuditQueryOptions
{
    public const string SectionName = "AuditQuery";

    /// <summary>
    /// How far back an audit query looks when the caller gives no <c>from</c>. Audit queries scan the log,
    /// so an unbounded default would make every unfiltered request read the whole history.
    /// </summary>
    public int DefaultDays { get; set; } = 30;
}

/// <summary>Fills in the start of an audit query's time range when the caller left it open.</summary>
public sealed class AuditQueryWindow(IOptions<AuditQueryOptions> options, TimeProvider clock)
{
    /// <summary>
    /// <paramref name="from"/> if given; otherwise <c>DefaultDays</c> before <paramref name="to"/>, or before now
    /// when <paramref name="to"/> is missing or in the future. An explicit <paramref name="from"/> reaches back as far as asked.
    /// </summary>
    public DateTimeOffset StartOf(DateTimeOffset? from, DateTimeOffset? to)
    {
        if (from is { } explicitFrom)
        {
            return explicitFrom;
        }

        var now = clock.GetUtcNow();
        var end = to is { } t && t < now ? t : now;
        return end.AddDays(-options.Value.DefaultDays);
    }
}
