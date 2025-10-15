namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class OnBehalfOfTokenAcquisitionPlugin
    : AccessTokenAcquisitionPluginBase, IPlugin
{
    protected override string AcquireAccessToken(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();

        var scopes = context.InputParameterOrDefault<string[]>("Scopes");

        var tokenAcquirer = serviceProvider.Get<IOnBehalfOfTokenService>();
        return tokenAcquirer.AcquireToken(scopes);
    }
}