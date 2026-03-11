using Microsoft.Identity.Client;
using Microsoft.IdentityModel.JsonWebTokens;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public sealed class KeyVaultCredentialsSilentTokenAcquisitionPlugin()
    : AccessTokenAcquisitionPluginBase(), IPlugin
{
    internal static class InputParameterNames
    {
        internal const string Scopes = nameof(Scopes);
        internal const string MsalAccountId = nameof(MsalAccountId);
        internal const string MsalV3Cache = nameof(MsalV3Cache);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1031: Do not catch general exception types",
        Justification = nameof(ITracingService)
        )]
    protected override string AcquireAccessToken(PluginContext pluginContext)
    {
        IPluginExecutionContext6 context = pluginContext.ExecutionContext;
        ParameterCollection inputs = context.InputParameters;
        ParameterCollection outputs = context.OutputParameters;
        ParameterCollection sharedVars = context.SharedVariables;

        _ = inputs.TryGetValue(
            InputParameterNames.Scopes,
            out string[]? scopes
            );
        scopes ??= [];

        if (!inputs.TryGetValue(
            InputParameterNames.MsalAccountId,
            out string msalAccountId) ||
            string.IsNullOrEmpty(msalAccountId)
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing or empty required parameter: {InputParameterNames.MsalAccountId}"
                );
        }

        JsonWebToken? msalv3cacheJwe = null;
        if (inputs.TryGetValue(
            InputParameterNames.MsalV3Cache,
            out string msalv3cacheEncoded) &&
            !string.IsNullOrEmpty(msalv3cacheEncoded)
            )
        {
            try
            {
                msalv3cacheJwe = JwtHandler.ReadJsonWebToken(msalv3cacheEncoded);
            }
            catch (Exception jweReadExcept)
            {
                pluginContext.ServiceProvider.Get<ITracingService>()?.Trace(
                    "While reading JWE specified in parameter '{0}': {1}",
                    InputParameterNames.MsalV3Cache,
                    jweReadExcept
                    );
            }
        }

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
            reqTenantId = pluginContext.ExecutionContext.TenantId;
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
        string clientId = reqAppId.GetValueOrDefault().ToString();

        EvaluateKeyVaultDataAccessPermissionsPlugin.ExecuteInternal(pluginContext, sharedVars);
        if (!sharedVars.TryGetValue(
            EvaluateKeyVaultDataAccessPermissionsPlugin.OutputParameterNames.UserHasSufficientPermissions,
            out bool userHasSufficientPermissions
            ) || !userHasSufficientPermissions)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.Forbidden,
                message: $"User with Entra Object ID {context.UserAzureActiveDirectoryObjectId} has insufficient permissions to access credentials stored in the referenced Key Vault resource."
                );
        }

        if (pluginContext.ResolvedKeyVaultReferenceEntity
            is not KeyVaultReference keyVaultReferenceEntity
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: "KeyVaultReference entity not availble."
                );
        }
        var keyVaultUri = keyVaultReferenceEntity.KeyVaultUri;
        var keyVaultDataName = keyVaultReferenceEntity.KeyName;
        _ = keyVaultReferenceEntity.TryGetAttributeValue(
            KeyVaultReference.Fields.KeyVersion,
            out string? keyVaultDataVersion
            );
        var keyVaultDataType = keyVaultReferenceEntity.KeyType;

        var msalBuilder = MsalPluginUtility.CreateMsalAppBuilder(
            pluginContext, reqTenantString,
            clientId,
            keyVaultUri,
            keyVaultDataType ?? (keytype)(-1),
            keyVaultDataName,
            keyVaultDataVersion,
            out var keyVaultSecurityKey,
            out var keyVaultEncryptCreds
            );

        IConfidentialClientApplication msalApp = msalBuilder.Build();
        MsalPluginUtility.RegisterMsalCachedSharedVariableStorage(
            msalApp,
            msalv3cacheJwe,
            keyVaultSecurityKey,
            sharedVars,
            pluginContext.ServiceProvider.Get<ITracingService>()
            );

        IAccount? msalAccount;
        try
        {
            msalAccount = msalApp.GetAccountAsync(msalAccountId)
                .GetAwaiter().GetResult();
        }
        catch (Exception msalAuthAccountExcept)
        {
            pluginContext.ServiceProvider.Get<ITracingService>()?.Trace(
                "Failed to retrieve MSAL cached account with identifier '{0}': {1}",
                msalAccountId,
                msalAuthAccountExcept
                );
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: msalAuthAccountExcept.Message
                );
        }
        if (msalAccount is null)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Unable to retrieve a cached Account to authenticate given the specified account identifier '{msalAccountId}'."
                );
        }

        var msalTokenAcquirer = msalApp.AcquireTokenSilent(
            scopes,
            msalAccount
            );
        AuthenticationResult msalAuthResult;
        try
        {
            msalAuthResult = msalTokenAcquirer.ExecuteAsync()
                .GetAwaiter().GetResult();
        }
        catch (Exception msalAuthExcept)
        {
            pluginContext.ServiceProvider.Get<ITracingService>()?.Trace(
                "MSAL silent authentication failed: {0}",
                msalAuthExcept
                );
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.Unauthorized,
                message: msalAuthExcept.Message
                );
        }

        MsalPluginUtility.EnsureUserPrivilegeForAuthResult(
            pluginContext, msalAuthResult
            );

        MsalPluginUtility.SetOutputParametersFromMsalAuthResult(
            msalAuthResult,
            inputs,
            sharedVars,
            outputs,
            keyVaultEncryptCreds
            );

        return msalAuthResult.AccessToken;
    }
}
