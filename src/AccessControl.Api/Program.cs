using System.Text.Json.Serialization;
using AccessControl.Api.Auth;
using AccessControl.Api.Endpoints;
using AccessControl.Api.Errors;
using AccessControl.Api.Hosting;
using AccessControl.Api.OpenApi;
using AccessControl.Api.RateLimiting;
using AccessControl.Application;
using AccessControl.Application.Abstractions;
using AccessControl.Infrastructure;
using AccessControl.Infrastructure.Storage;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HostFiltering;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAccessControlApplication(builder.Configuration)
    .AddAccessControlInfrastructure(builder.Configuration);

builder.Services.AddHttpContextAccessor();
// Replaces the application default (SystemActor) explicitly instead of relying on "last registration wins".
builder.Services.Replace(ServiceDescriptor.Singleton<IActorContext, HttpActorContext>());

builder.Services.AddOptions<ApiKeyOptions>()
    .Bind(builder.Configuration.GetSection(ApiKeyOptions.SectionName))
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<ApiKeyOptions>, ApiKeyOptionsValidator>();
builder.Services.AddSingleton<ProductionSettingsValidator>();
builder.Services.AddSingleton<IValidateOptions<StorageOptions>>(sp => sp.GetRequiredService<ProductionSettingsValidator>());
builder.Services.AddSingleton<IValidateOptions<HostFilteringOptions>>(sp => sp.GetRequiredService<ProductionSettingsValidator>());
builder.Services.AddOptions<HostFilteringOptions>().ValidateOnStart();

builder.Services
    .AddAuthentication(ApiKeyAuthenticationHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(
        ApiKeyAuthenticationHandler.SchemeName, _ => { });

builder.Services.AddAccessControlAuthorization();
builder.Services.AddAccessControlRateLimiting(builder.Configuration);

builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));

builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<ProblemDetailsExceptionHandler>();

if (builder.Environment.IsDevelopment())
{
    builder.Services.AddAccessControlSwagger();
}

var app = builder.Build();

app.UseExceptionHandler();
app.UseStatusCodePages();
if (app.Environment.IsDevelopment())
{
    app.UseAccessControlSwagger(); // before authentication, see SwaggerSetup
}
else
{
    // No HTTPS redirection: a client that sent its key over HTTP has already leaked it, so the key is
    // refused instead (Auth:RequireHttps) and the client must be fixed.
    app.UseHsts();
}

app.UseAuthentication();
app.UseRateLimiter(); // after authentication: budgets are per key, or per IP for anonymous callers
app.UseAuthorization();

// Readiness: storage writable with enough free space. Liveness: the process answers. Kept apart so that a full disk
// takes the instance out of rotation instead of getting it restarted in a loop.
app.MapHealthChecks(RateLimitingSetup.HealthPath).AllowAnonymous();
app.MapHealthChecks(RateLimitingSetup.HealthPath + "/live", new HealthCheckOptions { Predicate = _ => false }).AllowAnonymous();

app.MapGroup("/api/v1")
    .MapAdminEndpoints()
    .MapAccessEndpoints()
    .MapAuditEndpoints();

app.Run();

/// <summary>Exposed for integration tests (WebApplicationFactory).</summary>
public partial class Program;
