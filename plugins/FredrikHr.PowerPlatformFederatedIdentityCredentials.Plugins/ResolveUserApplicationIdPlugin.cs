using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.EntityInfo;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class ResolveUserApplicationIdPlugin()
    : PluginBase(ExecuteInternal), IPlugin
{
    internal static class OutputParameterName
    {
        internal const string UserApplicationId = nameof(UserApplicationId);
    }

    internal static void ExecuteInternal(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.Get<IPluginExecutionContext7>();
        if (!context.IsApplicationUser) return;

        IOrganizationService dataverseService = serviceProvider
            .Get<IOrganizationServiceFactory>()
            .CreateOrganizationService(default);
        Entity systemUserEntity = dataverseService.Retrieve(
            ApplicationSystemUserEntityInfo.EntityLogicalName,
            context.UserId,
            ApplicationSystemUserEntityInfo.ColumnSet
            );
        if (systemUserEntity.TryGetAttributeValue(
            ApplicationSystemUserEntityInfo.AttributeLogicalName.ApplicationId,
            out Guid applicationId
            ) && applicationId != Guid.Empty)
            context.OutputParameters[OutputParameterName.UserApplicationId] =
                applicationId;
    }
}