using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;

namespace AccessControl.Tests.Api;

public sealed class ApiSecurityTests : IAsyncLifetime, IDisposable
{
    private readonly ApiFactory _api = new();

    public Task InitializeAsync() => _api.SeedDoorsAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    public void Dispose() => _api.Dispose();

    [Fact]
    public async Task Requests_without_a_key_are_unauthorized()
    {
        var response = await _api.Client(apiKey: null).GetAsync("/api/v1/doors");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Keys_are_refused_over_plain_http()
    {
        var response = await _api.Client(ApiFactory.AdminKey, https: false).GetAsync("/api/v1/doors");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Health_is_anonymous()
    {
        var response = await _api.Client(apiKey: null).GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Controller_gets_a_decision_without_the_denial_reason()
    {
        var response = await _api.Client(ApiFactory.ControllerKey).PostAsJsonAsync(
            "/api/v1/access/requests", new { doorId = ApiFactory.AssignedDoorId, cardNumber = "AB:CD" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(body.GetProperty("granted").GetBoolean());
        Assert.False(body.TryGetProperty("reason", out _));

        // The reason is still in the audit trail.
        var events = await _api.Client(ApiFactory.AuditorKey).GetFromJsonAsync<JsonElement>("/api/v1/access/events");
        Assert.Equal("UnknownCredential", events.GetProperty("items")[0].GetProperty("reason").GetString());
    }

    [Fact]
    public async Task Controller_is_forbidden_at_doors_it_is_not_assigned_to_and_nothing_is_audited()
    {
        var response = await _api.Client(ApiFactory.ControllerKey).PostAsJsonAsync(
            "/api/v1/access/requests", new { doorId = ApiFactory.OtherDoorId, cardNumber = "AB:CD" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("door.not_assigned", problem.GetProperty("code").GetString());

        var events = await _api.Client(ApiFactory.AdminKey).GetFromJsonAsync<JsonElement>("/api/v1/access/events");
        Assert.Equal(0, events.GetProperty("total").GetInt32());
    }

    [Theory]
    [InlineData(ApiFactory.OperatorKey, "POST", "/api/v1/cardholders", HttpStatusCode.Created)]
    [InlineData(ApiFactory.OperatorKey, "POST", "/api/v1/doors", HttpStatusCode.Forbidden)]
    [InlineData(ApiFactory.OperatorKey, "POST", "/api/v1/doors/11111111-1111-1111-1111-111111111111/lockdown", HttpStatusCode.OK)]
    [InlineData(ApiFactory.OperatorKey, "POST", "/api/v1/doors/11111111-1111-1111-1111-111111111111/release", HttpStatusCode.Forbidden)]
    [InlineData(ApiFactory.OperatorKey, "GET", "/api/v1/access/events", HttpStatusCode.Forbidden)]
    [InlineData(ApiFactory.OperatorKey, "GET", "/api/v1/audit/changes", HttpStatusCode.Forbidden)]
    [InlineData(ApiFactory.AuditorKey, "GET", "/api/v1/doors", HttpStatusCode.OK)]
    [InlineData(ApiFactory.AuditorKey, "GET", "/api/v1/access/events", HttpStatusCode.OK)]
    [InlineData(ApiFactory.AuditorKey, "GET", "/api/v1/audit/changes", HttpStatusCode.OK)]
    [InlineData(ApiFactory.AuditorKey, "POST", "/api/v1/cardholders", HttpStatusCode.Forbidden)]
    [InlineData(ApiFactory.AuditorKey, "POST", "/api/v1/doors/11111111-1111-1111-1111-111111111111/lockdown", HttpStatusCode.Forbidden)]
    [InlineData(ApiFactory.ControllerKey, "GET", "/api/v1/doors", HttpStatusCode.Forbidden)]
    [InlineData(ApiFactory.ControllerKey, "GET", "/api/v1/access/events", HttpStatusCode.Forbidden)]
    [InlineData(ApiFactory.AdminKey, "POST", "/api/v1/doors", HttpStatusCode.Created)]
    [InlineData(ApiFactory.AdminKey, "POST", "/api/v1/doors/11111111-1111-1111-1111-111111111111/release", HttpStatusCode.OK)]
    [InlineData(ApiFactory.AdminKey, "GET", "/api/v1/audit/verify", HttpStatusCode.OK)]
    public async Task Roles_only_reach_their_endpoints(string key, string method, string path, HttpStatusCode expected)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        if (method == "POST" && !path.EndsWith("lockdown", StringComparison.Ordinal) && !path.EndsWith("release", StringComparison.Ordinal))
        {
            request.Content = JsonContent.Create(new { name = "Name", firstName = "Ada", lastName = "Lovelace" });
        }

        var response = await _api.Client(key).SendAsync(request);
        Assert.Equal(expected, response.StatusCode);
    }

    [Fact]
    public async Task Changes_are_attributed_to_the_key_that_made_them()
    {
        var created = await (await _api.Client(ApiFactory.OperatorKey).PostAsJsonAsync(
            "/api/v1/cardholders", new { firstName = "Ada", lastName = "Lovelace" })).Content.ReadFromJsonAsync<JsonElement>();
        var id = created.GetProperty("id").GetGuid();

        var changes = await _api.Client(ApiFactory.AuditorKey)
            .GetFromJsonAsync<JsonElement>($"/api/v1/audit/changes?entityId={id}");

        var entry = changes.GetProperty("items")[0];
        Assert.Equal("test-operator", entry.GetProperty("actor").GetString());
        Assert.Equal("Created", entry.GetProperty("kind").GetString());
        Assert.Equal("Ada", entry.GetProperty("after").GetProperty("firstName").GetString());
    }

    [Fact]
    public async Task Audit_logs_verify_over_the_api()
    {
        var reports = await _api.Client(ApiFactory.AuditorKey).GetFromJsonAsync<JsonElement>("/api/v1/audit/verify");
        Assert.All(reports.EnumerateArray(), r => Assert.True(r.GetProperty("isIntact").GetBoolean()));
    }
}

public sealed class ApiRateLimitTests
{
    [Fact]
    public async Task Controller_reads_beyond_the_limit_are_rejected()
    {
        using var api = new ApiFactory(new() { ["RateLimiting:DoorControllerPermitsPerMinute"] = "2" });
        await api.SeedDoorsAsync();
        var client = api.Client(ApiFactory.ControllerKey);

        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 3; i++)
        {
            statuses.Add((await client.PostAsJsonAsync(
                "/api/v1/access/requests", new { doorId = ApiFactory.AssignedDoorId, cardNumber = "AB" })).StatusCode);
        }

        Assert.Equal([HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.TooManyRequests], statuses);
    }

    [Fact]
    public async Task Guessing_keys_is_throttled_per_client()
    {
        using var api = new ApiFactory(new() { ["RateLimiting:AnonymousPermitsPerMinute"] = "2" });
        var client = api.Client("wrong-key");

        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 3; i++)
        {
            statuses.Add((await client.GetAsync("/api/v1/doors")).StatusCode);
        }

        Assert.Equal([HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized, HttpStatusCode.TooManyRequests], statuses);
    }
}

public sealed class ApiStartupValidationTests
{
    [Theory]
    [InlineData("Auth:ApiKeys:0:Sha256", "29b401073038b82dd8106b36b0e4105cb0fcf084a083efccb6f525c8973bd2d2", "published development key")]
    [InlineData("Auth:ApiKeys:3:Doors:0", "*", "only allowed in Development")]
    [InlineData("Auth:ApiKeys:3:Doors:0", "front-door", "is not a door id")]
    [InlineData("Auth:ApiKeys:1:Name", "test-admin", "is used more than once")]
    [InlineData("Auth:ApiKeys:2:Doors:0", "11111111-1111-1111-1111-111111111111", "only applies to DoorController")]
    public void Unsafe_key_configuration_stops_startup_outside_development(string setting, string value, string expected)
    {
        using var api = new ApiFactory(new() { [setting] = value });
        var ex = Assert.ThrowsAny<Exception>(() => api.Client(apiKey: null));
        Assert.Contains(expected, ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void A_controller_key_without_doors_stops_startup()
    {
        using var api = new ApiFactory(new() { ["Auth:ApiKeys:2:Role"] = "DoorController" });
        var ex = Assert.ThrowsAny<Exception>(() => api.Client(apiKey: null));
        Assert.Contains("must list the door ids", ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Development_allows_the_published_keys_and_wildcard_doors()
    {
        using var api = new ApiFactory(
            new()
            {
                // appsettings.Development.json is merged in by index: keep entry 1 a wildcard controller.
                ["Auth:ApiKeys:0:Sha256"] = "29b401073038b82dd8106b36b0e4105cb0fcf084a083efccb6f525c8973bd2d2",
                ["Auth:ApiKeys:1:Role"] = "DoorController",
                ["Auth:ApiKeys:3:Doors:0"] = "*",
            },
            environment: "Development");
        var response = await api.Client("dev-admin-key-change-me").GetAsync("/api/v1/doors");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}

public sealed class ApiSwaggerTests
{
    [Fact]
    public async Task Development_serves_swagger_ui_and_document_without_a_key()
    {
        // appsettings.Development.json is merged in by index: keep entry 1 a wildcard controller.
        using var api = new ApiFactory(new() { ["Auth:ApiKeys:1:Role"] = "DoorController" }, environment: "Development");
        var client = api.Client(apiKey: null);

        var ui = await client.GetAsync("/swagger/index.html");
        Assert.Equal(HttpStatusCode.OK, ui.StatusCode);

        var document = await client.GetFromJsonAsync<JsonElement>("/swagger/v1/swagger.json");
        Assert.True(document.GetProperty("paths").TryGetProperty("/api/v1/access/requests", out _));
        Assert.True(document.GetProperty("components").GetProperty("securitySchemes").TryGetProperty("ApiKey", out _));
    }

    [Theory]
    [InlineData("/swagger/index.html")]
    [InlineData("/swagger/v1/swagger.json")]
    public async Task Swagger_is_not_served_outside_development(string path)
    {
        using var api = new ApiFactory();
        var response = await api.Client(ApiFactory.AdminKey).GetAsync(path);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
