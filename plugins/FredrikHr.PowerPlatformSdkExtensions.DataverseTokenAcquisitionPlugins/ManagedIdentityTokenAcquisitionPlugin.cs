namespace FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins;

public class ManagedIdentityTokenAcquisitionPlugin :
    ServicePrincipalTokenAcquisitionPlugin, IPlugin
{
    protected override string AcquirePrimaryAccessToken(
        IServiceProvider serviceProvider,
        string resourceId
        )
    {
        var tokenAcquirer = serviceProvider.Get<IManagedIdentityService>();
        return tokenAcquirer.AcquireToken([$"{resourceId}/.default"]);
    }
}
