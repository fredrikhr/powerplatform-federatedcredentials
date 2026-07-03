using Microsoft.Identity.Client;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public sealed class AcquireForClientAccessTokenPlugin()
    : AcquireAccessTokenPlugin(), IPlugin
{
    internal static class InputParameterNames
    {
        internal const string Resource = nameof(Resource);
    }

    protected override string AcquireAccessTokenCore(
        IServiceProvider serviceProvider,
        PluginExecutionInformation info)
    {
        _ = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        info ??= new(serviceProvider);
        var context = serviceProvider.Get<IPluginExecutionContext2>();
        ParameterCollection inputs = context.InputParameters;

        _ = inputs.TryGetValue(
            InputParameterNames.Resource,
            out string? resource
            );
        if (string.IsNullOrEmpty(resource))
        {
            resource = info.ApplicationSystemUser?.ApplicationId?.ToString();
            if (string.IsNullOrEmpty(resource))
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Missing input parameter '{InputParameterNames.Resource}'."
                    );
            }
        }
        string[] scopes = [$"{resource}/.default"];

        if (!info.IsApplicationRequestingSelf &&
            !info.UserHasImpersonationPrivilege)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"User (Entra ID Object ID: {context.UserAzureActiveDirectoryObjectId}, Dataverse System User ID: {context.UserId}) does not have required privilege '{PluginExecutionInformation.PrivilegeNameImpersonation}'."
                );
        }

        if (info.IsRequestedApplicationPluginIdentity)
        {
            var pluginFicProvider = serviceProvider
                .Get<IManagedIdentityService>();
            return pluginFicProvider.AcquireToken(scopes);
        }

        if (info.ConfidentialClientApplicationOptions is not
            ConfidentialClientApplicationOptions msalOptions)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing required input parameters specifying the application for which an access token should be acquired."
                );
        }

        IConfidentialClientApplication msalClient = MsalPluginUtility
            .CreateMsalClientBuilder(msalOptions, info)
            .Build();
        AcquireTokenForClientParameterBuilder msalAcquire =
            msalClient.AcquireTokenForClient(scopes);
        AuthenticationResult msalAuthResult = msalAcquire.ExecuteAsync()
            .GetAwaiter().GetResult();
        return msalAuthResult.AccessToken;
    }
}
