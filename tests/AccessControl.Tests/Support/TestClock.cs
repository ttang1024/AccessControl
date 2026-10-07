namespace AccessControl.Tests.Support;

/// <summary>A settable clock so time-dependent rules can be tested deterministically.</summary>
internal sealed class TestClock(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;

    public override DateTimeOffset GetUtcNow() => Now.ToUniversalTime();
}
