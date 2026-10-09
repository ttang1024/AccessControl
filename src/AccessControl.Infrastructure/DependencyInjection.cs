using AccessControl.Application.Abstractions;
using AccessControl.Infrastructure.Persistence;
using AccessControl.Infrastructure.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

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

        services.AddSingleton(StoreConstraints.CardNumber);
        foreach (var foreignKey in StoreConstraints.ForeignKeys)
        {
            services.AddSingleton(foreignKey);
        }

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
