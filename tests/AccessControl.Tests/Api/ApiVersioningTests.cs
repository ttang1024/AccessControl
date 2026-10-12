using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AccessControl.Api.RateLimiting;
using Xunit;

namespace AccessControl.Tests.Api;

public sealed class ApiVersioningTests : IAsyncLifetime, IDisposable
{
    private readonly ApiFactory _api = new();

    public Task InitializeAsync() => _api.SeedDoorsAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    public void Dispose() => _api.Dispose();

    [Fact]
    public async Task Writes_from_a_stale_copy_get_412_instead_of_overwriting()
    {
        var admin = _api.Client(ApiFactory.AdminKey);
        var created = await admin.PostAsJsonAsync("/api/v1/doors", new { name = "Lab" });
        Assert.Equal("\"1\"", created.Headers.ETag?.Tag);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();

        var get = await admin.GetAsync($"/api/v1/doors/{id}");
        Assert.Equal("\"1\"", get.Headers.ETag?.Tag);

        var renamed = await SendAsync(admin, HttpMethod.Put, $"/api/v1/doors/{id}", "\"1\"", new { name = "Lab 1" });
        Assert.Equal(HttpStatusCode.OK, renamed.StatusCode);
        Assert.Equal("\"2\"", renamed.Headers.ETag?.Tag);

        var stale = await SendAsync(admin, HttpMethod.Put, $"/api/v1/doors/{id}", "\"1\"", new { name = "Lab B" });
        Assert.Equal(HttpStatusCode.PreconditionFailed, stale.StatusCode);
        Assert.Equal("precondition_failed", (await stale.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString());

        var malformed = await SendAsync(admin, HttpMethod.Post, $"/api/v1/doors/{id}/lockdown", "version-2", null);
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
        Assert.Equal("if_match.invalid", (await malformed.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString());

        // If-Match is optional.
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(admin, HttpMethod.Post, $"/api/v1/doors/{id}/lockdown", null, null)).StatusCode);
    }

    [Fact]
    public async Task Duplicate_card_errors_do_not_repeat_the_number()
    {
        var op = _api.Client(ApiFactory.OperatorKey);
        var ada = await (await op.PostAsJsonAsync("/api/v1/cardholders", new { firstName = "Ada", lastName = "Lovelace" }))
            .Content.ReadFromJsonAsync<JsonElement>();
        var path = $"/api/v1/cardholders/{ada.GetProperty("id").GetGuid()}/credentials";
        await op.PostAsJsonAsync(path, new { cardNumber = "0123456789ABCDEF" });

        var duplicate = await op.PostAsJsonAsync(path, new { cardNumber = "01:23:45:67:89:AB:CD:EF" });
        var body = await duplicate.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
        Assert.DoesNotContain("0123456789ABCDEF", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CDEF", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_second_instance_on_the_same_data_directory_fails_at_startup()
    {
        _api.Client(ApiFactory.AdminKey); // first instance started, holding the lock
        using var second = new ApiFactory(new() { ["Storage:DataDirectory"] = _api.DataDirectory });

        var ex = Assert.ThrowsAny<Exception>(() => second.Client(ApiFactory.AdminKey));
        Assert.Contains("in use by another process", ex.ToString(), StringComparison.Ordinal);
    }

    private static Task<HttpResponseMessage> SendAsync(HttpClient client, HttpMethod method, string path, string? ifMatch, object? body)
    {
        var request = new HttpRequestMessage(method, path) { Content = body is null ? null : JsonContent.Create(body) };
        if (ifMatch is not null)
        {
            request.Headers.TryAddWithoutValidation("If-Match", ifMatch);
        }

        return client.SendAsync(request);
    }
}

public sealed class ApiAbuseControlTests
{
    [Theory]
    [InlineData("203.0.113.7", "203.0.113.7")]
    [InlineData("::ffff:203.0.113.7", "203.0.113.7")]
    [InlineData("2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64")]
    [InlineData("2001:db8:1:2::1", "2001:db8:1:2::/64")]
    public void Rate_limits_group_ipv6_clients_by_their_64(string address, string partition) =>
        Assert.Equal(partition, RateLimitingSetup.ClientPartition(IPAddress.Parse(address)));
}
