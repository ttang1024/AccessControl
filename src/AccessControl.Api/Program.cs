using System.Text.Json.Serialization;
using AccessControl.Api.Auth;
using AccessControl.Api.Endpoints;
using AccessControl.Api.Errors;
using AccessControl.Api.OpenApi;
using AccessControl.Api.RateLimiting;
using AccessControl.Application;
using AccessControl.Application.Abstractions;
using AccessControl.Infrastructure;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAccessControlApplication()
    .AddAccessControlInfrastructure(builder.Configuration);

builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton<IActorContext, HttpActorContext>();

builder.Services.AddOptions<ApiKeyOptions>()
    .Bind(builder.Configuration.GetSection(ApiKeyOptions.SectionName))
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<ApiKeyOptions>, ApiKeyOptionsValidator>();

builder.Services
    .AddAuthentication(ApiKeyAuthenticationHandler.SchemeName)
    .AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(
        ApiKeyAuthenticationHandler.SchemeName, _ => { });

builder.Services.AddAccessControlAuthorization();
builder.Services.AddAccessControlRateLimiting(builder.Configuration);

builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
    o.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.Never;
});

builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<ProblemDetailsExceptionHandler>();

if (builder.Environment.IsDevelopment())
{
    builder.Services.AddAccessControlSwagger();
}

var app = builder.Build();

app.UseExceptionHandler();
app.UseStatusCodePages();
if (!app.Environment.IsDevelopment())
{
    // No HTTPS redirection: a client that sent its key over HTTP has already leaked it, so the key is
    // refused instead (Auth:RequireHttps) and the client must be fixed.
    app.UseHsts();
}

if (app.Environment.IsDevelopment())
{
    app.UseAccessControlSwagger(); // before authentication, see SwaggerSetup
}

app.UseAuthentication();
app.UseRateLimiter(); // after authentication: budgets are per key, or per IP for anonymous callers
app.UseAuthorization();

app.MapHealthChecks("/health").AllowAnonymous();

app.MapGroup("/api/v1")
    .MapAdminEndpoints()
    .MapAccessEndpoints()
    .MapAuditEndpoints();

app.Run();

/// <summary>Exposed for integration tests (WebApplicationFactory).</summary>
public partial class Program;
