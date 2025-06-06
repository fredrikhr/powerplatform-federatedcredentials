namespace FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins;

public class ManagedIdentityTokenAcquisitionPlugin
    : AccessTokenAcquisitionPluginBase, IPlugin
{
    protected override string AcquireAccessToken(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();
        var scopes = context.InputParameterOrDefault<string[]>("Scopes");

        var tokenAcquirer = serviceProvider.Get<IManagedIdentityService>();
        return context.PrimaryEntityId != Guid.Empty &&
            "managedidentity".Equals(context.PrimaryEntityName, StringComparison.OrdinalIgnoreCase)
            ? tokenAcquirer.AcquireToken(context.PrimaryEntityId, scopes)
            : tokenAcquirer.AcquireToken(scopes);
    }
}