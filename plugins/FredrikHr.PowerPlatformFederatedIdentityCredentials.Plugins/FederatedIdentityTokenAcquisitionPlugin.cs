using System.IdentityModel.Tokens.Jwt;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.EntityInfo;

using Microsoft.Identity.Client;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class FederatedIdentityTokenAcquisitionPlugin() :
    AccessTokenAcquisitionPluginBase(), IPlugin
{
    internal static class InputParameterName
    {
        internal const string ApplicationId = nameof(ApplicationId);
        internal const string ResourceId = nameof(ResourceId);
        internal const string AssertionAudience = nameof(AssertionAudience);
    }

    protected override string AcquireAccessToken(
        IServiceProvider serviceProvider
        )
    {
        var context = serviceProvider.Get<IPluginExecutionContext6>();
        Guid reqTenantId = context.TenantId;
        string reqTenantString = reqTenantId.ToString();
        bool hasReqAppId = context.InputParameters.TryGetValue(
            InputParameterName.ApplicationId, out Guid reqAppId
            ) && reqAppId != Guid.Empty;
        bool hasUserAppId = TryGetUserApplicationId(serviceProvider, out Guid userAppId) &&
            userAppId != Guid.Empty;
        if (!hasReqAppId)
        {
            reqAppId = hasUserAppId ? userAppId : throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"User is not an application user, and input parameter '{InputParameterName.ApplicationId}' was not specified."
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
                message: $"Entra Object ID {context.UserAzureActiveDirectoryObjectId} is missing privilege {PrivilegeNameImpersonation} for BU {context.BusinessUnitId}."
                );
        }

        if (context.InputParameterOrDefault<string>(InputParameterName.ResourceId)
            is not string reqResourceId
            )
            reqResourceId = reqAppId.ToString();

        bool hasPluginAppId = false;
        bool hasPluginTenantId = false;
        Guid pluginAppId = Guid.Empty;
        Guid pluginTenantId = context.TenantId;
        if (GetExecutingPluginManagedIdentityRecord(serviceProvider) is Entity pluginEntity)
        {
            hasPluginAppId = pluginEntity.TryGetAttributeValue(
                ManagedIdentityEntityInfo.AttributeLogicalName.ApplicationId,
                out pluginAppId
                );
            hasPluginTenantId = pluginEntity.TryGetAttributeValue(
                ManagedIdentityEntityInfo.AttributeLogicalName.TenantId,
                out pluginTenantId
                );
        }

        IEnumerable<string> reqScopes = [$"{reqResourceId}/.default"];
        bool pluginIsSameAsRequested =
            hasPluginAppId && reqAppId == pluginAppId &&
            (!hasPluginTenantId || pluginTenantId == reqTenantId);
        if (pluginIsSameAsRequested)
        {
            return serviceProvider.Get<IManagedIdentityService>()
                .AcquireToken(reqScopes);
        }

        return AcquireSecondaryAccessToken(serviceProvider,
            reqTenantString,
            reqAppId.ToString(),
            reqScopes
            );
    }

    protected virtual string AcquireSecondaryAccessToken(
        IServiceProvider serviceProvider,
        string tenantId,
        string clientId,
        IEnumerable<string> reqScopes
        )
    {
        const string clientAssertionName = "ClientAssertion";
        var context = serviceProvider.Get<IPluginExecutionContext6>();
        var federatedIdentity = serviceProvider.Get<IManagedIdentityService>();
        if (context.InputParameters.TryGetValue(
                    InputParameterName.AssertionAudience,
                    out string? assertionAudience
                    ) || string.IsNullOrEmpty(assertionAudience))
            assertionAudience = "api://AzureADTokenExchange";

        var azureEnvironmentInfo = serviceProvider.Get<IEnvironmentService>();
        IConfidentialClientApplication msalClient = ConfidentialClientApplicationBuilder
            .Create(clientId)
            .WithAuthority(
                azureEnvironmentInfo.AzureAuthorityHost.ToString(),
                tenantId
            )
            .WithClientAssertion(GetMsalClientAssertionAsync)
            .Build();
        try
        {
            AuthenticationResult msalResult = msalClient
                .AcquireTokenForClient(reqScopes)
                .ExecuteAsync().GetAwaiter().GetResult();
            return msalResult.AccessToken;
        }
        catch (MsalServiceException msalExcept)
        {
            string assertionIssuer = "<unknown>";
            string assertionSubject = "<unknown>";
            if (context.SharedVariables.TryGetValue(clientAssertionName, out string assertion))
            {
                JwtSecurityToken assertionJwt = JwtHandler.ReadJwtToken(assertion);
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
                [$"{assertionAudience}/.default"]
                );
            context.SharedVariables[clientAssertionName] = assertion;
            return Task.FromResult(assertion);
        }
    }
}