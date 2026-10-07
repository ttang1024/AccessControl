using AccessControl.Api.Auth;
using Microsoft.OpenApi.Models;

namespace AccessControl.Api.OpenApi;

/// <summary>
/// OpenAPI document and Swagger UI for local exploration. Development only: the UI would advertise the whole
/// API surface, and it invites pasting keys into a browser page.
/// </summary>
internal static class SwaggerSetup
{
    public static IServiceCollection AddAccessControlSwagger(this IServiceCollection services)
    {
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(o =>
        {
            o.SwaggerDoc("v1", new OpenApiInfo { Title = "Access Control API", Version = "v1" });

            // Full names, so request/response records with the same short name in different namespaces don't clash.
            o.CustomSchemaIds(t => t.FullName?.Replace('+', '.'));

            var scheme = new OpenApiSecurityScheme
            {
                Name = ApiKeyAuthenticationHandler.HeaderName,
                Type = SecuritySchemeType.ApiKey,
                In = ParameterLocation.Header,
                Description = "API key, e.g. a development key from CLAUDE.md.",
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = ApiKeyAuthenticationHandler.SchemeName },
            };
            o.AddSecurityDefinition(ApiKeyAuthenticationHandler.SchemeName, scheme);
            o.AddSecurityRequirement(new OpenApiSecurityRequirement { [scheme] = [] });
        });
        return services;
    }

    /// <summary>
    /// Serves <c>/swagger</c>. Call before authentication: these are middleware, not endpoints, so the
    /// fallback policy (authenticated users only) would otherwise block them.
    /// </summary>
    public static IApplicationBuilder UseAccessControlSwagger(this IApplicationBuilder app)
    {
        app.UseSwagger();
        app.UseSwaggerUI(); // /swagger, reading /swagger/v1/swagger.json
        return app;
    }
}
