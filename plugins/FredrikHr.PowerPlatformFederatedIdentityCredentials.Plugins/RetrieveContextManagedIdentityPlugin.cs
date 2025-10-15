using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.EntityInfo;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class RetrieveContextManagedIdentityPlugin()
    : PluginBase(ExecuteInternal), IPlugin
{
    internal static class OutputParameterNames
    {
        internal const string PluginAssemblyManagedIdentity = nameof(PluginAssemblyManagedIdentity);
    }

    internal static void ExecuteInternal(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();
        if (GetExecutingPluginManagedIdentityRecord(serviceProvider) is Entity managedIdentity)
        {
            context.OutputParameters[OutputParameterNames.PluginAssemblyManagedIdentity] =
                managedIdentity;
        }
    }

    private static Entity? GetExecutingPluginManagedIdentityRecord(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();
        var dataverseService = serviceProvider.Get<IOrganizationServiceFactory>()
            .CreateOrganizationService(null);
        Entity sdkStepEntity = dataverseService.Retrieve(
            context.OwningExtension?.LogicalName!
            ?? SdkMessageProcessingStepEntityInfo.EntityLogicalName,
            context.OwningExtension?.Id ?? Guid.Empty,
            SdkMessageProcessingStepEntityInfo.ColumnSet
            );
        if (
            !sdkStepEntity.TryGetAttributeValue(
                SdkMessageProcessingStepEntityInfo.AttributeLogicalName.PluginTypeId,
                out EntityReference? pluginTypeEntityRef
                ) ||
                pluginTypeEntityRef is null
            )
        { return null; }

        Entity pluginTypeEntity = dataverseService.Retrieve(
            PluginTypeEntityInfo.EntityLogicalName,
            pluginTypeEntityRef.Id,
            PluginTypeEntityInfo.ColumnSet
            );
        if (
            !pluginTypeEntity.TryGetAttributeValue(
                PluginTypeEntityInfo.AttributeLogicalName.PluginAssemblyId,
                out EntityReference? pluginAssemblyEntityRef
                ) ||
            pluginAssemblyEntityRef is null
            )
        { return null; }

        Entity pluginAssemblyEntity = dataverseService.Retrieve(
            PluginAssemblyEntityInfo.EntityLogicalName,
            pluginAssemblyEntityRef.Id,
            PluginAssemblyEntityInfo.ColumnSet
            );
        if (
            pluginAssemblyEntity.TryGetAttributeValue(
                PluginAssemblyEntityInfo.AttributeLogicalName.ManagedIdentityId,
                out EntityReference? managedIdentityEntityRef
                ) &&
            managedIdentityEntityRef is not null
            )
        {
            return dataverseService.Retrieve(
                ManagedIdentityEntityInfo.EntityLogicalName,
                managedIdentityEntityRef.Id,
                ManagedIdentityEntityInfo.ColumnSet
                );
        }

        if (
            !pluginAssemblyEntity.TryGetAttributeValue(
                PluginAssemblyEntityInfo.AttributeLogicalName.PackageId,
                out EntityReference? pluginPackageEntityRef
                ) ||
            pluginPackageEntityRef is null
            )
        { return null; }

        Entity pluginPackageEntity = dataverseService.Retrieve(
            PluginPackageEntityInfo.EntityLogicalName,
            pluginPackageEntityRef.Id,
            PluginPackageEntityInfo.ColumnSet
            );
#pragma warning disable IDE0046 // Convert to conditional expression
        if (
            pluginPackageEntity.TryGetAttributeValue(
                PluginPackageEntityInfo.AttributeLogicalName.ManagedIdentityId,
                out managedIdentityEntityRef
                ) &&
                managedIdentityEntityRef is not null
            )
        {
            return dataverseService.Retrieve(
                ManagedIdentityEntityInfo.EntityLogicalName,
                managedIdentityEntityRef.Id,
                ManagedIdentityEntityInfo.ColumnSet
                );
        }
#pragma warning restore IDE0046 // Convert to conditional expression

        return null;
    }
}