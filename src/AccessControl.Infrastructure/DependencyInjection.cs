using System.Text.Json;
using AccessControl.Application.Abstractions;
using AccessControl.Application.Errors;
using AccessControl.Infrastructure.Persistence;
using AccessControl.Infrastructure.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace AccessControl.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddAccessControlInfrastructure(
        this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<StorageOptions>()
            .Bind(configuration.GetSection(StorageOptions.SectionName))
            .Validate(o => !string.IsNullOrWhiteSpace(o.DataDirectory), "Storage:DataDirectory is required.")
            .Validate(o => o.AuditRetentionDays is null or > 0, "Storage:AuditRetentionDays must be positive when set.")
            .ValidateOnStart();

        services.AddSingleton(new UniqueIndex(
            Collections.Credentials,
            Collections.CardNumberIndex,
            body => body.TryGetProperty("cardNumber", out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null,
            ConflictException.DuplicateCardNumber));

        services.AddSingleton<JsonLinesChangeLog>();
        services.AddSingleton<IChangeAuditLog>(sp => sp.GetRequiredService<JsonLinesChangeLog>());
        services.AddSingleton<DocumentStore>();
        services.AddSingleton<JsonLinesAccessEventLog>();
        services.AddSingleton<IAccessEventLog>(sp => sp.GetRequiredService<JsonLinesAccessEventLog>());
        services.AddSingleton<IAuditIntegrity, AuditIntegrity>();

        services.AddScoped<DocumentSession>();
        services.AddScoped<IUnitOfWork>(sp => sp.GetRequiredService<DocumentSession>());
        services.AddScoped<ICardholderRepository, CardholderRepository>();
        services.AddScoped<ICredentialRepository, CredentialRepository>();
        services.AddScoped<IDoorRepository, DoorRepository>();
        services.AddScoped<IScheduleRepository, ScheduleRepository>();
        services.AddScoped<IAccessGroupRepository, AccessGroupRepository>();

        services.AddHealthChecks().AddCheck<StorageHealthCheck>("storage");
        return services;
    }
}
