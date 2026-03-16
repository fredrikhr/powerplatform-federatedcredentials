using Microsoft.Identity.Client;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using Azure.Security.KeyVault.Certificates;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;
using Azure.Security.KeyVault.Secrets;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

internal static class MsalPluginUtility
{
    internal static class InputParameterNames
    {
        internal const string MsalV3Cache = nameof(MsalV3Cache);
    }

    internal static class SharedVariableNames
    {
        internal const string MsalV3Cache = nameof(MsalV3Cache);
        internal const string MsalV3CacheChanged = nameof(MsalV3CacheChanged);
    }

    internal static class OutputParameterNames
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

    private static readonly JsonWebTokenHandler JwtHandler = new();

    internal static ConfidentialClientApplicationBuilder GetMsalClientBuilderDefault(
        PluginContext pluginContext,
        string tenantId,
        string clientId
        )
    {
        Uri msIdpInstance = pluginContext.ServiceProvider
            .Get<IEnvironmentService>()
            .AzureAuthorityHost;
        return ConfidentialClientApplicationBuilder.Create(clientId)
            .WithAuthority(msIdpInstance.ToString(), tenantId);
    }

    internal static ConfidentialClientApplicationBuilder CreateMsalAppBuilder(
        PluginContext pluginContext,
        string tenantId,
        string clientId,
        string keyVaultUri,
        keytype keyVaultDataType,
        string keyVaultDataName,
        string? keyVaultDataVersion,
        out SecurityKey keyVaultSecurityKey,
        out EncryptingCredentials keyVaultEncryptCreds
        )
    {
        ConfidentialClientApplicationBuilder msalBuilder;
        switch (keyVaultDataType)
        {
            case keytype.Secret:
                KeyVaultSecret keyVaultSecretData = KeyVaultPluginUtility.GetKeyVaultSecretAsync(
                    pluginContext,
                    keyVaultUri,
                    keyVaultDataName,
                    keyVaultDataVersion
                    ).GetAwaiter().GetResult();
                string keyVaultSecretValue = keyVaultSecretData.Value;
                keyVaultSecurityKey = KeyVaultPluginUtility.GetKeyVaultSecretSecurityKey(
                    keyVaultSecretData,
                    keySizeBits: 256
                    );
                keyVaultEncryptCreds = new EncryptingCredentials(
                    keyVaultSecurityKey,
                    alg: JwtConstants.DirectKeyUseAlg,
                    enc: SecurityAlgorithms.Aes128CbcHmacSha256
                    );
                msalBuilder = GetMsalClientBuilderDefault(
                    pluginContext, tenantId,
                    clientId
                    ).WithClientSecret(keyVaultSecretValue);
                break;

            case keytype.Certificate:
            case keytype.CertificateWithX5c:
                KeyVaultCertificate keyVaultCertificateInfo;
                RsaSecurityKey keyVaultRsaKey;
                (keyVaultCertificateInfo, keyVaultRsaKey) = KeyVaultPluginUtility.GetKeyVaultPrivateRsaSecurityKeyAsync(
                    pluginContext, keyVaultUri, keyVaultDataName,
                    keyVaultDataVersion
                    ).GetAwaiter().GetResult();
                keyVaultRsaKey.KeyId = keyVaultCertificateInfo.KeyId.ToString();
                keyVaultSecurityKey = keyVaultRsaKey;
                keyVaultEncryptCreds = new EncryptingCredentials(
                    keyVaultSecurityKey,
                    alg: SecurityAlgorithms.RsaOAEP,
                    enc: SecurityAlgorithms.Aes128CbcHmacSha256
                    );
                var keyVaultAssertionProvider = KeyVaultPluginUtility.GetKeyVaultCertificateAssertionProvider(
                    keyVaultCertificateInfo,
                    keyVaultRsaKey,
                    sendX5c: keyVaultDataType == keytype.CertificateWithX5c
                    );
                msalBuilder = GetMsalClientBuilderDefault(
                    pluginContext, tenantId,
                    clientId
                    ).WithClientAssertion(keyVaultAssertionProvider);
                break;

            default:
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Invalid Key Vault Resource Type specified: {keyVaultDataType}"
                    );
        }

        return msalBuilder;
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1031: Do not catch general exception types",
        Justification = nameof(ITracingService)
        )]
    internal static void RegisterMsalCachedSharedVariableStorage(
        IClientApplicationBase msalApp,
        JsonWebToken? msalv3CacheJwe,
        SecurityKey msalCacheDecryptKey,
        ParameterCollection sharedVariables,
        ITracingService? trace
        )
    {
        sharedVariables[SharedVariableNames.MsalV3CacheChanged] = false;
        if (msalv3CacheJwe is not null)
        {
            try
            {
                string msalv3Cache = JwtHandler.DecryptToken(
                    msalv3CacheJwe,
                    new() { TokenDecryptionKey = msalCacheDecryptKey }
                    );
                sharedVariables[SharedVariableNames.MsalV3Cache] = msalv3Cache;
            }
            catch (Exception jweDecryptExcept)
            {
                trace?.Trace(
                    "While decrypting JWE containing MSAL v3 cache: {0}",
                    jweDecryptExcept
                    );
                sharedVariables[SharedVariableNames.MsalV3Cache] = null;
            }
        }
        else
        {
            sharedVariables[SharedVariableNames.MsalV3Cache] = null;
        }

        msalApp.UserTokenCache.SetBeforeAccess(SharedVariablesToMsalCache);
        msalApp.UserTokenCache.SetAfterAccess(MsalCacheToSharedVariables);

        [System.Diagnostics.CodeAnalysis.SuppressMessage(
            "Design",
            "CA1031: Do not catch general exception types",
            Justification = nameof(ITracingService)
            )]
        void SharedVariablesToMsalCache(TokenCacheNotificationArgs context)
        {
            if (!sharedVariables.TryGetValue(
                SharedVariableNames.MsalV3Cache,
                out string msalv3CacheBase64Url) ||
                string.IsNullOrEmpty(msalv3CacheBase64Url)
                )
                return;

            byte[] msalv3cacheData;
            try
            {
                msalv3cacheData = Base64UrlEncoder.DecodeBytes(msalv3CacheBase64Url);
            }
            catch (Exception base64DecodeExcept)
            {
                trace?.Trace(
                    "While decoding MSAL v3 as Base64-URL encoded string: {0}",
                    base64DecodeExcept
                    );
                return;
            }

            try
            {
                context.TokenCache.DeserializeMsalV3(msalv3cacheData);
            }
            catch (Exception msalCacheDeserializeExcept)
            {
                trace?.Trace(
                    "While deserializing MSAL v3 token cache data: {0}",
                    msalCacheDeserializeExcept
                    );
                return;
            }
        }

        void MsalCacheToSharedVariables(TokenCacheNotificationArgs context)
        {
            if (!context.HasStateChanged) return;
            byte[] msalv3cacheData = context.TokenCache.SerializeMsalV3();
            string msalv3CacheBase64Url = Base64UrlEncoder.Encode(msalv3cacheData);
            sharedVariables[SharedVariableNames.MsalV3Cache] = msalv3CacheBase64Url;
            sharedVariables[SharedVariableNames.MsalV3CacheChanged] = true;
        }
    }

    internal static void EnsureUserPrivilegeForAuthResult(
        PluginContext pluginContext,
        AuthenticationResult authResult
        )
    {
        var context = pluginContext.ExecutionContext;
        if (!Guid.TryParse(authResult.TenantId, out Guid msalAuthTenantId) ||
            context.TenantId != msalAuthTenantId ||
            !Guid.TryParse(authResult.UniqueId, out Guid msalAuthUserId) ||
            context.UserAzureActiveDirectoryObjectId != msalAuthUserId
            )
        {
            if (!pluginContext.UserHasImpersonationPrivilege)
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.Forbidden,
                    message: $"An access token was successfully obtained, but the access token authenticates a different user (or the authenticated user is unknown) and the calling user does not have the {PluginContext.PrivilegeNameImpersonation} privilege."
                    );
            }
        }
    }

    internal static void SetOutputParametersFromMsalAuthResult(
        AuthenticationResult authResult,
        ParameterCollection? inputs,
        ParameterCollection? sharedVariables,
        ParameterCollection outputs,
        EncryptingCredentials? msalCacheEncryptCreds
        )
    {
        if (authResult.Account is { HomeAccountId.Identifier: string msalAccountId } &&
            !string.IsNullOrEmpty(msalAccountId)
            )
        {
            outputs[OutputParameterNames.MsalAccountId] = msalAccountId;
        }
        outputs[OutputParameterNames.CorrelationId] = authResult.CorrelationId;
        outputs[OutputParameterNames.ExpiresOn] = authResult.ExpiresOn.UtcDateTime;
        outputs[OutputParameterNames.Scopes] = authResult.Scopes;
        outputs[OutputParameterNames.TenantId] = authResult.TenantId;
        outputs[OutputParameterNames.TokenType] = authResult.TokenType;
        outputs[OutputParameterNames.UniqueId] = authResult.UniqueId;
        if (authResult.AdditionalResponseParameters is
            { Count: > 0 } additionalResponseParams)
        {
            outputs[OutputParameterNames.AdditionalResponseParameters] = new Entity()
            {
                Attributes = [
                    ..additionalResponseParams
                    .Select(kvp => new KeyValuePair<string, object>(kvp.Key, kvp.Value))
                ],
            };
        }
        if (authResult.AuthenticationResultMetadata is not null)
        {
            outputs[OutputParameterNames.AuthenticationResultMetadata] =
                GetMsalAuthMetadataEntity(authResult.AuthenticationResultMetadata);
        }
        if (!string.IsNullOrEmpty(authResult.IdToken))
        {
            outputs[OutputParameterNames.IdToken] = authResult.IdToken;
            outputs[OutputParameterNames.IdJsonWebToken] = AccessTokenAcquisitionPluginBase.GetJwtEntity(authResult.IdToken);
        }

        string? msalv3cacheEncoded = null;
        string? msalv3CacheBase64Url = null;
        if (sharedVariables?.TryGetValue(
            SharedVariableNames.MsalV3CacheChanged,
            out bool msalv3cacheChanged) ?? false &&
            msalv3cacheChanged &&
            sharedVariables.TryGetValue(
            SharedVariableNames.MsalV3Cache,
            out msalv3CacheBase64Url) &&
            !string.IsNullOrEmpty(msalv3CacheBase64Url)
            )
        {
            msalv3cacheEncoded = JwtHandler.EncryptToken(
                msalv3CacheBase64Url,
                msalCacheEncryptCreds
                );
            outputs[OutputParameterNames.MsalV3Cache] = msalv3cacheEncoded;
        }
        else if (inputs?.TryGetValue(
            InputParameterNames.MsalV3Cache,
            out msalv3cacheEncoded) ?? false)
        {
            outputs[OutputParameterNames.MsalV3Cache] = msalv3cacheEncoded;
        }
        sharedVariables?.Remove(SharedVariableNames.MsalV3Cache);
        sharedVariables?.Remove(SharedVariableNames.MsalV3CacheChanged);

        static Entity GetMsalAuthMetadataEntity(
            AuthenticationResultMetadata metadata
            )
        {
            return new()
            {
                Attributes =
                {
                    { nameof(metadata.TokenSource), metadata.TokenSource.ToString() },
                    { nameof(metadata.TokenEndpoint), metadata.TokenEndpoint },
                    { nameof(metadata.DurationTotalInMs), metadata.DurationTotalInMs },
                    { nameof(metadata.DurationInCacheInMs), metadata.DurationInCacheInMs },
                    { nameof(metadata.DurationInHttpInMs), metadata.DurationInHttpInMs },
                    { nameof(metadata.RefreshOn), metadata.RefreshOn?.UtcDateTime },
                    { nameof(metadata.CacheRefreshReason), metadata.CacheRefreshReason.ToString() },
                    { nameof(metadata.CacheLevel), metadata.CacheLevel.ToString() },
                    { nameof(metadata.RegionDetails.RegionOutcome), metadata.RegionDetails?.RegionOutcome.ToString() },
                    { nameof(metadata.RegionDetails.RegionUsed), metadata.RegionDetails?.RegionUsed },
                    { $"Region{nameof(metadata.RegionDetails.AutoDetectionError)}", metadata.RegionDetails?.AutoDetectionError },
                },
            };
        }
    }
}