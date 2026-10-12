using AccessControl.Application;
using AccessControl.Application.Abstractions;
using AccessControl.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AccessControl.Tests.Support;

/// <summary>
/// Real application + infrastructure wiring over a throw-away data directory.
/// Each <see cref="Scope{T}"/> call behaves like one HTTP request (fresh unit of work).
/// </summary>
internal sealed class TestHost : IDisposable
{
    private readonly ServiceProvider _provider;

    public TestHost(DateTimeOffset? now = null, string? dataDirectory = null, IDictionary<string, string?>? settings = null)
    {
        DataDirectory = dataDirectory ?? Path.Combine(Path.GetTempPath(), "acs-tests-" + Guid.NewGuid().ToString("N"));
        Clock = new TestClock(now ?? new DateTimeOffset(2026, 10, 7, 9, 0, 0, TimeSpan.FromHours(13)));

        var values = new Dictionary<string, string?>
        {
            ["Storage:DataDirectory"] = DataDirectory,
            ["Storage:FlushAuditToDisk"] = "false",
        };
        foreach (var (key, value) in settings ?? new Dictionary<string, string?>())
        {
            values[key] = value;
        }

        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(Clock);
        services.AddSingleton<IActorContext>(Actor);
        services.AddAccessControlApplication(configuration);
        services.AddAccessControlInfrastructure(configuration);
        _provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
    }

    public string DataDirectory { get; }

    public TestClock Clock { get; }

    /// <summary>Who the change trail records as acting; settable per step.</summary>
    public TestActor Actor { get; } = new();

    public async Task<TResult> Scope<TService, TResult>(Func<TService, Task<TResult>> action)
        where TService : notnull
    {
        using var scope = _provider.CreateScope();
        return await action(scope.ServiceProvider.GetRequiredService<TService>());
    }

    public async Task Scope<TService>(Func<TService, Task> action)
        where TService : notnull
    {
        using var scope = _provider.CreateScope();
        await action(scope.ServiceProvider.GetRequiredService<TService>());
    }

    public IServiceScope CreateScope() => _provider.CreateScope();

    public T GetRequiredService<T>()
        where T : notnull => _provider.GetRequiredService<T>();

    /// <summary>Disposes the services but keeps the data directory, to test reload from disk.</summary>
    public void Stop() => _provider.Dispose();

    public void Dispose()
    {
        _provider.Dispose();
        if (Directory.Exists(DataDirectory))
        {
            Directory.Delete(DataDirectory, recursive: true);
        }
    }
}

internal sealed class TestActor : IActorContext
{
    public string Actor { get; set; } = "test";

    public bool CanGrantRestrictedAccess { get; set; } = true;
}
