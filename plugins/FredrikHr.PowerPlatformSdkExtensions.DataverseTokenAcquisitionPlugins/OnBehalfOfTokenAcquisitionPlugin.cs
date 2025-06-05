namespace FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins;

public class OnBehalfOfTokenAcquisitionPlugin : IPlugin
{
    public void Execute(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();
        var outputs = context.OutputParameters;

        var scopes = context.InputParameterOrDefault<string[]>("Scopes");

        var tokenAcquirer = serviceProvider.Get<IOnBehalfOfTokenService>();
        try
        {
            string accessToken = tokenAcquirer.AcquireToken(scopes);
            outputs["AccessToken"] = accessToken;
        }
        catch (Exception except)
        {
            throw new InvalidPluginExecutionException(
                message: except.Message,
                exception: except
                );
        }
    }
}