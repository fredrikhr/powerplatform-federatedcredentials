using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class RetrieveContextManagedIdentityPlugin : PluginBase, IPlugin
{
    internal static class OutputParameterNames
    {
        internal const string PluginAssemblyManagedIdentity = nameof(PluginAssemblyManagedIdentity);
    }

    protected override void ExecuteCore(IServiceProvider serviceProvider)
    {
        ExecuteInternal(serviceProvider);
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
        var sdkStepEntity = dataverseService.Retrieve(
            context.OwningExtension?.LogicalName!
            ?? SdkMessageProcessingStep.EntityLogicalName,
            context.OwningExtension?.Id ?? Guid.Empty,
            SdkMessageProcessingStep.ColumnSet
            ).ToEntity<SdkMessageProcessingStep>();
        if (!sdkStepEntity.TryGetAttributeValue(
                SdkMessageProcessingStep.Fields.PluginTypeId,
                out EntityReference? pluginTypeEntityRef
                ) ||
                pluginTypeEntityRef is null
            )
        { return null; }

        var pluginTypeEntity = dataverseService.Retrieve(
            PluginType.EntityLogicalName,
            pluginTypeEntityRef.Id,
            PluginType.ColumnSet
            ).ToEntity<PluginType>();
        if (pluginTypeEntity.PluginAssemblyId is not EntityReference pluginAssemblyEntityRef)
        { return null; }

        var pluginAssemblyEntity = dataverseService.Retrieve(
            PluginAssembly.EntityLogicalName,
            pluginAssemblyEntityRef.Id,
            PluginAssembly.ColumnSet
            ).ToEntity<PluginAssembly>();
        if (pluginAssemblyEntity.ManagedIdentityId is EntityReference managedIdentityEntityRef)
        {
            return dataverseService.Retrieve(
                ManagedIdentity.EntityLogicalName,
                managedIdentityEntityRef.Id,
                ManagedIdentity.ColumnSet
                );
        }

        if (pluginAssemblyEntity.PackageId is not EntityReference pluginPackageEntityRef)
        { return null; }

        var pluginPackageEntity = dataverseService.Retrieve(
            PluginPackage.EntityLogicalName,
            pluginPackageEntityRef.Id,
            PluginPackage.ColumnSet
            ).ToEntity<PluginPackage>();
#pragma warning disable IDE0046 // Convert to conditional expression
        if ((managedIdentityEntityRef = pluginPackageEntity.managedidentityid) is not null)
        {
            return dataverseService.Retrieve(
                ManagedIdentity.EntityLogicalName,
                managedIdentityEntityRef.Id,
                ManagedIdentity.ColumnSet
                );
        }
#pragma warning restore IDE0046 // Convert to conditional expression

        return null;
    }
}