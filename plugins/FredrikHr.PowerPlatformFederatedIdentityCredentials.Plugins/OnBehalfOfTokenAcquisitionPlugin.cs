namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class OnBehalfOfTokenAcquisitionPlugin
    : AccessTokenAcquisitionPluginBase, IPlugin
{
    protected override string AcquireAccessToken(PluginContext pluginContext)
    {
        _ = pluginContext ?? throw new ArgumentNullException(nameof(pluginContext));
        var scopes = pluginContext.ExecutionContext
            .InputParameterOrDefault<string[]>("Scopes");

        var tokenAcquirer = pluginContext.ServiceProvider
            .Get<IOnBehalfOfTokenService>();
        return tokenAcquirer.AcquireToken(scopes);
    }
}