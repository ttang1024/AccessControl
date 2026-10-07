using AccessControl.Application.Abstractions;
using AccessControl.Application.Access;
using AccessControl.Application.AccessGroups;
using AccessControl.Application.Audit;
using AccessControl.Application.Cardholders;
using AccessControl.Application.Credentials;
using AccessControl.Application.Doors;
using AccessControl.Application.Schedules;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AccessControl.Application;

public static class DependencyInjection
{
    /// <summary>Registers application services. Persistence ports must be registered by an infrastructure module.</summary>
    public static IServiceCollection AddAccessControlApplication(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IActorContext, SystemActor>();

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
