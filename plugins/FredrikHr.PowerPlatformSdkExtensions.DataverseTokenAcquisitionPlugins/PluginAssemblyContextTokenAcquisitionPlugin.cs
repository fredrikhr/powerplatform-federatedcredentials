namespace FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins;

public class PluginAssemblyContextTokenAcquisitionPlugin : IPlugin
{
    public void Execute(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();
        var outputs = context.OutputParameters;

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
        catch (ArgumentNullException)
        {
            throw new InvalidPluginExecutionException(
                message: $"Input parameter {nameof(AuthenticationType)} must not be null.",
                httpStatus: PluginHttpStatusCode.BadRequest
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
        try
        {
            outputs["AccessToken"] = tokenAcquirer.AcquireToken(
                authority,
                resourceId,
                authenticationType
                );
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