using System.Security.Cryptography;
using System.Text;
using AccessControl.Application.Abstractions;
using AccessControl.Domain.Doors;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AccessControl.Tests.Api;

/// <summary>
/// The real API host (Production environment unless told otherwise) over a temp data directory, with one key
/// per role. The controller key is bound to <see cref="AssignedDoorId"/> only; both doors are pre-seeded.
/// </summary>
internal sealed class ApiFactory(Dictionary<string, string?>? overrides = null, string environment = "Production")
    : WebApplicationFactory<Program>
{
    public const string AdminKey = "test-admin-key-0123456789";
    public const string OperatorKey = "test-operator-key-0123456789";
    public const string AuditorKey = "test-auditor-key-0123456789";
    public const string ControllerKey = "test-controller-key-0123456789";

    public static readonly Guid AssignedDoorId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    public static readonly Guid OtherDoorId = Guid.Parse("22222222-2222-2222-2222-222222222222");

    public string DataDirectory { get; } = Path.Combine(Path.GetTempPath(), "acs-api-tests-" + Guid.NewGuid().ToString("N"));

    public static string Hash(string key) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)));

    public static Dictionary<string, string?> Keys() => new()
    {
        ["Auth:ApiKeys:0:Name"] = "test-admin",
        ["Auth:ApiKeys:0:Role"] = "Admin",
        ["Auth:ApiKeys:0:Sha256"] = Hash(AdminKey),
        ["Auth:ApiKeys:1:Name"] = "test-operator",
        ["Auth:ApiKeys:1:Role"] = "Operator",
        ["Auth:ApiKeys:1:Sha256"] = Hash(OperatorKey),
        ["Auth:ApiKeys:2:Name"] = "test-auditor",
        ["Auth:ApiKeys:2:Role"] = "Auditor",
        ["Auth:ApiKeys:2:Sha256"] = Hash(AuditorKey),
        ["Auth:ApiKeys:3:Name"] = "test-controller",
        ["Auth:ApiKeys:3:Role"] = "DoorController",
        ["Auth:ApiKeys:3:Sha256"] = Hash(ControllerKey),
        ["Auth:ApiKeys:3:Doors:0"] = AssignedDoorId.ToString(),
    };

    public HttpClient Client(string? apiKey, bool https = true)
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(https ? "https://localhost" : "http://localhost"),
            AllowAutoRedirect = false,
        });
        if (apiKey is not null)
        {
            client.DefaultRequestHeaders.Add("X-Api-Key", apiKey);
        }

        return client;
    }

    public async Task SeedDoorsAsync()
    {
        using var scope = Services.CreateScope();
        var doors = scope.ServiceProvider.GetRequiredService<IDoorRepository>();
        doors.Add(Door.Create(AssignedDoorId, "Assigned", null));
        doors.Add(Door.Create(OtherDoorId, "Other", null));
        await scope.ServiceProvider.GetRequiredService<IUnitOfWork>().CommitAsync(default);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        var settings = Keys();
        settings["Storage:DataDirectory"] = DataDirectory;
        settings["Storage:FlushAuditToDisk"] = "false";
        settings["Storage:MinimumFreeDiskBytes"] = "1";
        settings["Storage:AuditHmacKey"] = "test-audit-hmac-key-0123456789abcdef";
        settings["Storage:CardNumberKey"] = "test-card-number-key-0123456789abcdef";
        settings["AllowedHosts"] = "localhost";
        foreach (var (key, value) in overrides ?? [])
        {
            settings[key] = value;
        }

        builder.UseEnvironment(environment);
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(settings));
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            DeleteDataDirectory();
        }
    }

    /// <summary>
    /// The app's own thread disposes its services (writing the store's final checkpoint) just after the factory has
    /// stopped the host, so the directory can still be written to for a moment: retry briefly.
    /// </summary>
    private void DeleteDataDirectory()
    {
        for (var attempt = 1; Directory.Exists(DataDirectory); attempt++)
        {
            try
            {
                Directory.Delete(DataDirectory, recursive: true);
            }
            catch (IOException) when (attempt < 20)
            {
                Thread.Sleep(50);
            }
        }
    }
}
