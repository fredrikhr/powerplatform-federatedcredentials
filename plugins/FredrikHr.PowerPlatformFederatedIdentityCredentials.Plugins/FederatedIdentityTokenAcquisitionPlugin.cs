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

    protected override string AcquireAccessToken(PluginContext pluginContext)
    {
        _ = pluginContext ?? throw new ArgumentNullException(nameof(pluginContext));
        var context = pluginContext.ExecutionContext;
        if (
            pluginContext.RequestedManagedIdentity
            is not ManagedIdentity reqManagedIdentity
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: "Requested ManagedIdentity entity is not available."
                );
        }
        if (reqManagedIdentity.TenantId is not Guid reqTenantId || reqTenantId == Guid.Empty)
            reqTenantId = context.TenantId;
        string reqTenantString = reqTenantId.ToString();
        Guid? reqAppId = reqManagedIdentity.ApplicationId;
        bool hasReqAppId = (reqAppId ?? Guid.Empty) != Guid.Empty;
        Guid? userAppId = pluginContext.UserApplicationId;
        bool hasUserAppId = userAppId.HasValue && userAppId != Guid.Empty;
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
            !pluginContext.UserHasImpersonationPrivilege
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.Forbidden,
                message: $"Entra Object ID {context.UserAzureActiveDirectoryObjectId} is missing privilege {PluginContext.PrivilegeNameImpersonation}."
                );
        }

        if (context.InputParameterOrDefault<string>(InputParameterNames.ResourceId)
            is not string reqResourceId
            )
        {
            reqResourceId = reqAppId.ToString();
        }

        if (
            pluginContext.PluginManagedIdentity
            is not ManagedIdentity pluginEntity
            )
        {
            throw new InvalidPluginExecutionException(
                "Plugin assembly ManagedIdentity entity is not available."
                );
        }
        Guid? pluginAppId = pluginEntity.ApplicationId;
        Guid? pluginTenantId = pluginEntity.TenantId;
        bool hasPluginAppId = pluginAppId.HasValue;
        bool hasPluginTenantId = pluginTenantId.HasValue;

        bool pluginIsSameAsRequested =
            hasPluginAppId && reqAppId == pluginAppId &&
            (!hasPluginTenantId || pluginTenantId == reqTenantId);
        IEnumerable<string> reqScopes = [$"{reqResourceId}/.default"];
        return pluginIsSameAsRequested
            ? AcquirePrimaryAccessToken(pluginContext, reqScopes)
            : AcquireSecondaryAccessToken(
                pluginContext,
                reqTenantString,
                reqAppId.ToString(),
                reqScopes
                );
    }

    private static string AcquirePrimaryAccessToken(
        PluginContext pluginContext,
        IEnumerable<string> scopes
        )
    {
        return pluginContext.ServiceProvider.Get<IManagedIdentityService>()
            .AcquireToken(scopes);
    }

    protected virtual string AcquireSecondaryAccessToken(
        PluginContext pluginContext,
        string tenantId,
        string clientId,
        IEnumerable<string> scopes
        )
    {
        _ = pluginContext ?? throw new ArgumentNullException(nameof(pluginContext));

        if (pluginContext.RequestedManagedIdentity
            is { ManagedIdentityId: Guid reqManagedIdentityEntityId } &&
            reqManagedIdentityEntityId != Guid.Empty
            )
        {
            PluginPackageManagedIdentityService pluginManagedIdentity =
                new(pluginContext.ServiceProvider);
            return pluginManagedIdentity.AcquireToken(
                reqManagedIdentityEntityId,
                scopes
                );
        }

        const string clientAssertionName = "ClientAssertion";
        var federatedIdentity = pluginContext.ServiceProvider
            .Get<IManagedIdentityService>();
        if (pluginContext.Inputs.TryGetValue(
            InputParameterNames.AssertionAudience,
            out string? assertionAudience
            ) || string.IsNullOrEmpty(assertionAudience)
            )
        { assertionAudience = "api://AzureADTokenExchange"; }

        var azureEnvironmentInfo = pluginContext.ServiceProvider
            .Get<IEnvironmentService>();
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
                .AcquireTokenForClient(scopes)
                .ExecuteAsync().GetAwaiter().GetResult();
            return msalResult.AccessToken;
        }
        catch (MsalServiceException msalExcept)
        {
            string assertionIssuer = "<unknown>";
            string assertionSubject = "<unknown>";
            if (pluginContext.ExecutionContext.SharedVariables
                .TryGetValue(clientAssertionName, out string assertion)
                )
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
            string assertion = federatedIdentity.AcquireToken(scopes);
            pluginContext.ExecutionContext
                .SharedVariables[clientAssertionName] = assertion;
            return Task.FromResult(assertion);
        }
    }
}