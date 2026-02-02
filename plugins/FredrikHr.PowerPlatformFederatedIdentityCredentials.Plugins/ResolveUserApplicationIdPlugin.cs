using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class ResolveUserApplicationIdPlugin : PluginBase, IPlugin
{
    internal static class OutputParameterName
    {
        internal const string UserApplicationId = nameof(UserApplicationId);
    }

    protected override void ExecuteCore(IServiceProvider serviceProvider)
    {
        ExecuteInternal(serviceProvider);
    }

    internal static void ExecuteInternal(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.Get<IPluginExecutionContext7>();
        if (!context.IsApplicationUser) return;

        IOrganizationService dataverseService = serviceProvider
            .Get<IOrganizationServiceFactory>()
            .CreateOrganizationService(default);
        var systemUserEntity = dataverseService.Retrieve(
            SystemUser.EntityLogicalName,
            context.UserId,
            SystemUser.ApplicationSystemUserColumnSet
            ).ToEntity<SystemUser>();
        if (
            systemUserEntity.ApplicationId is Guid applicationId &&
            applicationId != Guid.Empty
            )
            context.OutputParameters[OutputParameterName.UserApplicationId] =
                applicationId;
    }
}