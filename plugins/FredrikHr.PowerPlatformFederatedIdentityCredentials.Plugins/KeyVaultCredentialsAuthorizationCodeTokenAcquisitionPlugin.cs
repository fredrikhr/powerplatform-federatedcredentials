using Microsoft.Identity.Client;
using Microsoft.IdentityModel.JsonWebTokens;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public sealed class KeyVaultCredentialsAuthorizationCodeTokenAcquisitionPlugin()
    : AccessTokenAcquisitionPluginBase(), IPlugin
{
    internal static class InputParameterNames
    {
        internal const string Scopes = nameof(Scopes);
        internal const string AuthorizationCode = nameof(AuthorizationCode);
        internal const string PkceCodeVerifier = nameof(PkceCodeVerifier);
        internal const string MsalV3Cache = nameof(MsalV3Cache);
    }

    internal static new class OutputParameterNames
    {
        internal const string MsalV3Cache = nameof(MsalV3Cache);
        internal const string MsalAccountId = nameof(MsalAccountId);
        internal const string CorrelationId = nameof(AuthenticationResult.CorrelationId);
        internal const string ExpiresOn = nameof(AuthenticationResult.ExpiresOn);
        internal const string Scopes = nameof(AuthenticationResult.Scopes);
        internal const string TenantId = nameof(AuthenticationResult.TenantId);
        internal const string TokenType = nameof(AuthenticationResult.TokenType);
        internal const string UniqueId = nameof(AuthenticationResult.UniqueId);
        internal const string AdditionalResponseParameters = nameof(AuthenticationResult.AdditionalResponseParameters);
        internal const string AuthenticationResultMetadata = nameof(AuthenticationResult.AuthenticationResultMetadata);
        internal const string IdToken = nameof(AuthenticationResult.IdToken);
        internal const string IdJsonWebToken = nameof(IdJsonWebToken);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1031: Do not catch general exception types",
        Justification = nameof(ITracingService)
        )]
    protected override string AcquireAccessToken(
        IServiceProvider serviceProvider
        )
    {
        var context = serviceProvider.Get<IPluginExecutionContext6>();
        ParameterCollection inputs = context.InputParameters;
        ParameterCollection outputs = context.OutputParameters;
        ParameterCollection sharedVars = context.SharedVariables;

        if (!inputs.TryGetValue(
            InputParameterNames.AuthorizationCode,
            out string authorizationCode) ||
            string.IsNullOrEmpty(authorizationCode)
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing required parameter: {InputParameterNames.AuthorizationCode}"
                );
        }
        if (!inputs.TryGetValue(
            InputParameterNames.Scopes,
            out string[] scopes) ||
            scopes is not { Length: > 0 }
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing required parameter: {InputParameterNames.Scopes}"
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
                serviceProvider.Get<ITracingService>()?.Trace(
                    "While reading JWE specified in parameter '{0}': {1}",
                    InputParameterNames.MsalV3Cache,
                    jweReadExcept
                    );
            }
        }

        ResolveUserApplicationIdPlugin.ExecuteInternal(serviceProvider);
        RetrieveRequestedManagedIdentityPlugin.ExecuteInternal(serviceProvider);
        var reqManagedIdentity = outputs[
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
        bool hasUserAppId = outputs.TryGetValue(
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
        string clientId = reqAppId.GetValueOrDefault().ToString();
        EvaluateKeyVaultDataAccessPermissionsPlugin.ExecuteInternal(serviceProvider);
        if (!outputs.TryGetValue(
            EvaluateKeyVaultDataAccessPermissionsPlugin.OutputParameterNames.UserHasSufficientPermissions,
            out bool userHasSufficientPermissions
            ) || !userHasSufficientPermissions)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.Forbidden,
                message: $"User with Entra Object ID {context.UserAzureActiveDirectoryObjectId} has insufficient permissions to access credentials stored in the referenced Key Vault resource."
                );
        }

        var keyVaultReferenceEntity = outputs[
            ResolveKeyVaultReferencePlugin.OutputParameterNames.KeyVaultReference
            ] switch
        {
            KeyVaultReference e => e,
            Entity e => e.ToEntity<KeyVaultReference>(),
            _ => throw new InvalidPluginExecutionException("KeyVaultReference entity not availble."),
        };
        var keyVaultUri = keyVaultReferenceEntity.KeyVaultUri;
        var keyVaultDataName = keyVaultReferenceEntity.KeyName;
        _ = keyVaultReferenceEntity.TryGetAttributeValue(
            KeyVaultReference.Fields.KeyVersion,
            out string? keyVaultDataVersion
            );
        var keyVaultDataType = keyVaultReferenceEntity.KeyType;

        var msalBuilder = MsalPluginUtility.CreateMsalAppBuilder(
            serviceProvider,
            reqTenantString,
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
            serviceProvider.Get<ITracingService>()
            );

        var msalTokenAcquirer = msalApp
            .AcquireTokenByAuthorizationCode(scopes, authorizationCode);
        if (inputs.TryGetValue(
            InputParameterNames.PkceCodeVerifier,
            out string pkceCodeVerifier) &&
            !string.IsNullOrEmpty(pkceCodeVerifier)
            )
        {
            msalTokenAcquirer = msalTokenAcquirer
                .WithPkceCodeVerifier(pkceCodeVerifier);
        }

        AuthenticationResult msalAuthResult = msalTokenAcquirer.ExecuteAsync()
            .GetAwaiter().GetResult();

        MsalPluginUtility.EnsureUserPrivilegeForAuthResult(
            serviceProvider,
            msalAuthResult
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