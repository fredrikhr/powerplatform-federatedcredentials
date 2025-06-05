
namespace FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins;

public class ManagedIdentityTokenAcquisitionPlugin : IPlugin
{
    public void Execute(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();
        var outputs = context.OutputParameters;

        var scopes = context.InputParameterOrDefault<string[]>("Scopes");

        var tokenAcquirer = serviceProvider.Get<IManagedIdentityService>();
        try
        {
            string accessToken = context.PrimaryEntityId != Guid.Empty &&
                "managedidentity".Equals(context.PrimaryEntityName, StringComparison.OrdinalIgnoreCase)
                ? tokenAcquirer.AcquireToken(context.PrimaryEntityId, scopes)
                : tokenAcquirer.AcquireToken(scopes);
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