namespace FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins;

public class PluginAssemblyContextTokenAcquisitionPlugin
    : AccessTokenAcquisitionPluginBase, IPlugin
{
    protected override string AcquireAccessToken(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();

        var authority = context.InputParameterOrDefault<string>("Authority");
        var resourceId = context.InputParameterOrDefault<string>("ResourceId");
        AuthenticationType authenticationType;
        var authenticationTypeString = context.InputParameterOrDefault<string?>(nameof(AuthenticationType));
        try
        {
            authenticationType = string.IsNullOrEmpty(authenticationTypeString)
                ? AuthenticationType.ManagedIdentity
                : (AuthenticationType)Enum.Parse(
                    typeof(AuthenticationType),
                    authenticationTypeString,
                    ignoreCase: true
                    );
        }
        catch (ArgumentException argExcept)
        {
            throw new InvalidPluginExecutionException(
                message: argExcept.Message,
                httpStatus: PluginHttpStatusCode.BadRequest
                );
        }

        var tokenAcquirer = serviceProvider.Get<IAssemblyAuthenticationContext>();
        return tokenAcquirer.AcquireToken(
            authority,
            resourceId,
            authenticationType
            );
    }
}