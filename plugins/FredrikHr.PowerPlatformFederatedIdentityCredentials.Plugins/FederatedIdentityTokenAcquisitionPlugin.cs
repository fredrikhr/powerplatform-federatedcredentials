using Microsoft.Identity.Client;

using Microsoft.IdentityModel.JsonWebTokens;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class FederatedIdentityTokenAcquisitionPlugin() :
    AccessTokenAcquisitionPluginBase(), IPlugin
{
    internal static class InputParameterNames
    {
        internal const string ResourceId = nameof(ResourceId);
        internal const string AssertionAudience = nameof(AssertionAudience);
    }

    protected override string AcquireAccessToken(
        IServiceProvider serviceProvider
        )
    {
        var context = serviceProvider.Get<IPluginExecutionContext6>();
        ResolveUserApplicationIdPlugin.ExecuteInternal(serviceProvider);
        RetrieveRequestedManagedIdentityPlugin.ExecuteInternal(serviceProvider);
        var reqManagedIdentity = context.OutputParameters[
            RetrieveRequestedManagedIdentityPlugin.OutputParameterNames.RequestedManagedIdentity
            ] switch
        {
            ManagedIdentity e => e,
            Entity e => e.ToEntity<ManagedIdentity>(),
            _ => throw new InvalidPluginExecutionException("Requested ManagedIdentity entity is not available."),
        };
        if (reqManagedIdentity.TenantId is not Guid reqTenantId || reqTenantId == Guid.Empty)
            reqTenantId = context.TenantId;
        string reqTenantString = reqTenantId.ToString();
        Guid? reqAppId = reqManagedIdentity.ApplicationId;
        bool hasReqAppId = (reqAppId ?? Guid.Empty) != Guid.Empty;
        bool hasUserAppId = context.OutputParameters.TryGetValue(
            ResolveUserApplicationIdPlugin.OutputParameterName.UserApplicationId,
            out Guid userAppId
            ) && userAppId != Guid.Empty;
        if (!hasReqAppId)
        {
            reqAppId = hasUserAppId ? userAppId : throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"User is not an application user, and input parameter '{RetrieveRequestedManagedIdentityPlugin.InputParameterNames.ApplicationId}' was not specified."
                );
        }

        bool userIsSameAsRequested = hasUserAppId && reqAppId == userAppId;
        if (
            !userIsSameAsRequested &&
            !CheckUserHasImpersonatePrivilege(serviceProvider)
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.Forbidden,
                message: $"Entra Object ID {context.UserAzureActiveDirectoryObjectId} is missing privilege {PrivilegeNameImpersonation}."
                );
        }

        if (context.InputParameterOrDefault<string>(InputParameterNames.ResourceId)
            is not string reqResourceId
            )
        {
            reqResourceId = reqAppId.ToString();
        }

        RetrieveContextManagedIdentityPlugin.ExecuteInternal(serviceProvider);
        var pluginEntity = context.OutputParameters[
            RetrieveContextManagedIdentityPlugin.OutputParameterNames.PluginAssemblyManagedIdentity
            ] switch
        {
            ManagedIdentity e => e,
            Entity e => e.ToEntity<ManagedIdentity>(),
            _ => throw new InvalidPluginExecutionException("Plugin assembly ManagedIdentity entity is not available."),
        };
        Guid? pluginAppId = pluginEntity.ApplicationId;
        Guid? pluginTenantId = pluginEntity.TenantId;
        bool hasPluginAppId = pluginAppId.HasValue;
        bool hasPluginTenantId = pluginTenantId.HasValue;

        bool pluginIsSameAsRequested =
            hasPluginAppId && reqAppId == pluginAppId &&
            (!hasPluginTenantId || pluginTenantId == reqTenantId);
        return pluginIsSameAsRequested
            ? AcquirePrimaryAccessToken(serviceProvider, reqResourceId)
            : AcquireSecondaryAccessToken(serviceProvider,
                reqTenantString,
                reqAppId.ToString(),
                reqResourceId
                );
    }

    private static string AcquirePrimaryAccessToken(
        IServiceProvider serviceProvider,
        string resourceId
        )
    {
        var authInfo = serviceProvider.Get<IEnvironmentService>();
        var pluginAuthContext = serviceProvider.Get<IAssemblyAuthenticationContext>();
        return pluginAuthContext.AcquireToken(
            authInfo.AzureAuthorityHost.ToString(),
            resourceId,
            AuthenticationType.ManagedIdentity
            );
    }

    protected virtual string AcquireSecondaryAccessToken(
        IServiceProvider serviceProvider,
        string tenantId,
        string clientId,
        string resourceId
        )
    {
        IEnumerable<string> msalScopes = [$"{resourceId}/.default"];
        const string clientAssertionName = "ClientAssertion";
        var context = serviceProvider.Get<IPluginExecutionContext6>();
        var federatedIdentity = serviceProvider.Get<IAssemblyAuthenticationContext>();
        if (context.InputParameters.TryGetValue(
                    InputParameterNames.AssertionAudience,
                    out string? assertionAudience
                    ) || string.IsNullOrEmpty(assertionAudience))
            assertionAudience = "api://AzureADTokenExchange";

        var azureEnvironmentInfo = serviceProvider.Get<IEnvironmentService>();
        string authorityInstanceUrl = azureEnvironmentInfo.AzureAuthorityHost.ToString();
        IConfidentialClientApplication msalClient = ConfidentialClientApplicationBuilder
            .Create(clientId)
            .WithAuthority(
                authorityInstanceUrl,
                tenantId
            )
            .WithClientAssertion(GetMsalClientAssertionAsync)
            .Build();
        try
        {
            AuthenticationResult msalResult = msalClient
                .AcquireTokenForClient(msalScopes)
                .ExecuteAsync().GetAwaiter().GetResult();
            return msalResult.AccessToken;
        }
        catch (MsalServiceException msalExcept)
        {
            string assertionIssuer = "<unknown>";
            string assertionSubject = "<unknown>";
            if (context.SharedVariables.TryGetValue(clientAssertionName, out string assertion))
            {
                JsonWebToken assertionJwt = JwtHandler.ReadJsonWebToken(assertion);
                assertionIssuer = assertionJwt.Issuer;
                assertionSubject = assertionJwt.Subject;
            }
            Dictionary<string, string> msalDetails = [];
            foreach (KeyValuePair<string, string> msalKvp in msalExcept.AdditionalExceptionData)
                msalDetails[msalKvp.Key] = msalKvp.Value;
            msalDetails[nameof(Type)] = msalExcept.GetType().ToString();
            throw new InvalidPluginExecutionException(
                message: $"Assertion: {{issuer: {assertionIssuer}, subject: {assertionSubject}}}. {msalExcept.Message}",
                httpStatus: PluginHttpStatusCode.Forbidden,
                exceptionDetails: msalDetails
                );
        }

        Task<string> GetMsalClientAssertionAsync(AssertionRequestOptions msalRequest)
        {
            string assertion = federatedIdentity.AcquireToken(
                authorityInstanceUrl,
                resourceId,
                AuthenticationType.ManagedIdentity
                );
            context.SharedVariables[clientAssertionName] = assertion;
            return Task.FromResult(assertion);
        }
    }
}