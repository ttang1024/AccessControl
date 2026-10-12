using AccessControl.Application.Abstractions;
using AccessControl.Application.Access;
using AccessControl.Application.AccessGroups;
using AccessControl.Application.Audit;
using AccessControl.Application.Cardholders;
using AccessControl.Application.Credentials;
using AccessControl.Application.Doors;
using AccessControl.Application.Schedules;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AccessControl.Application;

public static class DependencyInjection
{
    /// <summary>
    /// Registers application services. Persistence ports must be registered by an infrastructure module, and
    /// <see cref="IActorContext"/> by the host.
    /// </summary>
    public static IServiceCollection AddAccessControlApplication(
        this IServiceCollection services, IConfiguration configuration)
    {
        services.TryAddSingleton(TimeProvider.System);

        services.AddOptions<AuditQueryOptions>()
            .Bind(configuration.GetSection(AuditQueryOptions.SectionName))
            .Validate(o => o.DefaultDays > 0, "AuditQuery:DefaultDays must be positive.")
            .ValidateOnStart();
        services.AddSingleton<AuditQueryWindow>();

        services.AddScoped<CardholderService>();
        services.AddScoped<CredentialService>();
        services.AddScoped<DoorService>();
        services.AddScoped<ScheduleService>();
        services.AddScoped<AccessGroupService>();
        services.AddScoped<AccessService>();
        services.AddScoped<AuditService>();
        return services;
    }
}
