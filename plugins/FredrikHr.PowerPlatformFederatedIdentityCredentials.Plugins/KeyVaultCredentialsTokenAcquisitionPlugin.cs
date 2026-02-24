using System.Reflection;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;

using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class KeyVaultCredentialsTokenAcquisitionPlugin
    : FederatedIdentityTokenAcquisitionPlugin, IPlugin
{
    static KeyVaultCredentialsTokenAcquisitionPlugin()
    {
        _ = typeof(RSA);
        _ = typeof(Oid);
        _ = typeof(HashAlgorithmName);
        _ = typeof(X509Certificate2);
        _ = typeof(RSACryptoServiceProvider);
        _ = typeof(TokenCredential);
        _ = typeof(CertificateClient);
        _ = typeof(CryptographyClient);
    }

    protected override string AcquireSecondaryAccessToken(
        IServiceProvider serviceProvider,
        string tenantId,
        string clientId,
        IEnumerable<string> reqScopes
        )
    {
        var context = serviceProvider.Get<IPluginExecutionContext2>();
        EvaluateKeyVaultDataAccessPermissionsPlugin.ExecuteInternal(serviceProvider);
        if (!context.OutputParameters.TryGetValue(
            EvaluateKeyVaultDataAccessPermissionsPlugin.OutputParameterNames.UserHasSufficientPermissions,
            out bool userHasSufficientPermissions
            ) || !userHasSufficientPermissions)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.Forbidden,
                message: $"User with Entra Object ID {context.UserAzureActiveDirectoryObjectId} has insufficient permissions to access credentials stored in the referenced Key Vault resource."
                );
        }

        var keyVaultDataPermissions = (KeyVaultDataAccessPermisions)(int)context.OutputParameters[
            EvaluateKeyVaultDataAccessPermissionsPlugin.OutputParameterNames.UserEffectivePermissions
            ];

        var keyVaultReferenceEntity = context.OutputParameters[
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

        ConfidentialClientApplicationBuilder msalBuilder = keyVaultDataType switch
        {
            keytype.Secret =>
                GetMsalClientBuilderUsingClientSecret(
                    serviceProvider, tenantId, clientId,
                    keyVaultUri, keyVaultDataName
                    ),
            keytype.Certificate or
            keytype.CertificateWithX5c =>
                GetMsalClientBuilderUsingCertificatePrivateKey(
                    serviceProvider, tenantId, clientId,
                    keyVaultUri, keyVaultDataName, keyVaultDataVersion
                    ),
            _ => GetMsalClientBuilderDefault(serviceProvider, tenantId, clientId),
        };
        IConfidentialClientApplication msalApp = msalBuilder.Build();
        AuthenticationResult msalAuthResult = msalApp
            .AcquireTokenForClient(reqScopes).ExecuteAsync()
            .GetAwaiter().GetResult();

        return msalAuthResult.AccessToken;
    }

    private static ConfidentialClientApplicationBuilder GetMsalClientBuilderDefault(
        IServiceProvider serviceProvider,
        string tenantId,
        string clientId
        )
    {
        Uri msIdpInstance = serviceProvider.Get<IEnvironmentService>()
            .AzureAuthorityHost;
        return ConfidentialClientApplicationBuilder.Create(clientId)
            .WithAuthority(msIdpInstance.ToString(), tenantId);
    }

    private static ConfidentialClientApplicationBuilder GetMsalClientBuilderUsingClientSecret(
        IServiceProvider serviceProvider,
        string tenantId,
        string clientId,
        string keyVaultUri,
        string keyVaultSecretName
        )
    {
        var keyVaultClient = serviceProvider.Get<IKeyVaultClient>();
        keyVaultClient.PreferredAuthType = AuthenticationType.ManagedIdentity;

        var keyVaultSecretValue = keyVaultClient.GetSecret(
            keyVaultUri,
            keyVaultSecretName
            );

        return GetMsalClientBuilderDefault(serviceProvider, tenantId, clientId)
            .WithClientSecret(keyVaultSecretValue);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability",
        "CA2000:Dispose objects before losing scope",
        Justification = nameof(ConfidentialClientApplicationBuilder.WithCertificate)
        )]
    private static ConfidentialClientApplicationBuilder GetMsalClientBuilderUsingCertificatePrivateKey(
        IServiceProvider serviceProvider,
        string tenantId,
        string clientId,
        string keyVaultUrl,
        string keyVaultSecretName,
        string? keyVaultSecretVersion = null
        )
    {
        TokenCredential tokenCredential = AzureResourceContextProvider
            .GetOrCreateTokenCredential(serviceProvider);

        return GetMsalClientBuilderDefault(serviceProvider, tenantId, clientId)
            .WithCertificate(GetClientCertifacteWithPrivateKey().GetAwaiter().GetResult())
            ;

        async Task<X509Certificate2> GetClientCertifacteWithPrivateKey()
        {
            KeyVaultCertificate keyVaultCertificateInfo = await
                GetKeyVaultCertificateAsync(serviceProvider, keyVaultUrl, keyVaultSecretName, keyVaultSecretVersion)
                .ConfigureAwait(continueOnCapturedContext: false);
            X509Certificate2 keyVaultCertificate = new(keyVaultCertificateInfo.Cer);
            CryptographyClientOptions keyVaultCryptoClientOptions = new();
            KeyResolver keyVaultKeyResolver = new(tokenCredential, keyVaultCryptoClientOptions);
            CryptographyClient keyVaultCryptoClient = await keyVaultKeyResolver
                .ResolveAsync(keyVaultCertificateInfo.KeyId)
                .ConfigureAwait(continueOnCapturedContext: false);
            RSAKeyVault keyVaultRsaKey = await keyVaultCryptoClient
                .CreateRSAAsync()
                .ConfigureAwait(continueOnCapturedContext: false);
            keyVaultCertificate.PrivateKey = keyVaultRsaKey;
            return keyVaultCertificate;
        }

        async Task<string> GetClientAssertionAsync(AssertionRequestOptions context)
        {
            KeyVaultCertificate keyVaultCertificateInfo = await
                GetKeyVaultCertificateAsync(serviceProvider, keyVaultUrl, keyVaultSecretName, keyVaultSecretVersion)
                .ConfigureAwait(continueOnCapturedContext: false);
            using SHA256 sha256 = SHA256.Create();
            string keyVaultCertificateThumbprintS256 = Base64UrlEncoder.Encode(
                sha256.ComputeHash(keyVaultCertificateInfo.Cer)
                );
            CryptographyClientOptions keyVaultCryptoClientOptions = new();
            KeyResolver keyVaultKeyResolver = new(tokenCredential, keyVaultCryptoClientOptions);
            CryptographyClient keyVaultCryptoClient = await keyVaultKeyResolver
                .ResolveAsync(keyVaultCertificateInfo.KeyId)
                .ConfigureAwait(continueOnCapturedContext: false);
            using RSAKeyVault keyVaultRsaKey = await keyVaultCryptoClient
                .CreateRSAAsync()
                .ConfigureAwait(continueOnCapturedContext: false);

            SecurityTokenDescriptor assertionDesc = new()
            {
                Audience = context.TokenEndpoint,
                Issuer = context.ClientID,
                Subject = new([new(JwtRegisteredClaimNames.Sub, context.ClientID)]),
                SigningCredentials = new(
                    new RsaSecurityKey(keyVaultRsaKey),
                    SecurityAlgorithms.RsaSsaPssSha256
                    ),
                AdditionalInnerHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    { JwtHeaderParameterNames.X5t + "#S256", keyVaultCertificateThumbprintS256 }
                },
            };
            string assertionEncoded = JwtHandler.CreateEncodedJwt(assertionDesc);
            return assertionEncoded;
        }
    }

    // Loading and using CertificateClient from assembly hosted in plugin sandbox worker environment
    // fails, retrieve KeyVaultCertificate resource manually using HTTP-client instead.
    private static async Task<KeyVaultCertificate> GetKeyVaultCertificateAsync(
        IServiceProvider serviceProvider,
        string keyVaultUrl,
        string keyVaultCertificateName,
        string? keyVaultCertificateVersion = null
        )
    {
        Type keyVaultJsonSerializationInterfaceType = Type.GetType(
            "Azure.Security.KeyVault.IJsonDeserializable, Azure.Security.KeyVault.Certificates, PublicKeyToken=92742159e12e44c8",
            throwOnError: true, ignoreCase: true
            );
        var keyVaultAuthCtx = serviceProvider.Get<IAssemblyAuthenticationContext2>();
        TokenCredential tokenCredential = AzureResourceContextProvider
            .GetOrCreateTokenCredential(serviceProvider);
        Uri keyVaultUri = new(keyVaultUrl, UriKind.Absolute);
        string keyVaultApiVersion = typeof(CertificateClientOptions).InvokeMember(
            "GetVersionString",
            BindingFlags.Instance |
            BindingFlags.Public | BindingFlags.NonPublic |
            BindingFlags.InvokeMethod,
            target: new CertificateClientOptions(),
            args: [],
            binder: Type.DefaultBinder,
            culture: System.Globalization.CultureInfo.InvariantCulture
            ) as string ?? "2025-07-01";
        string keyVaultCertificateRelativeUrl = string.IsNullOrWhiteSpace(keyVaultCertificateVersion)
            ? $"/certificates/{Uri.EscapeUriString(keyVaultCertificateName)}?api-version={keyVaultApiVersion}"
            : $"/certificates/{Uri.EscapeUriString(keyVaultCertificateName)}/{Uri.EscapeUriString(keyVaultCertificateVersion)}?api-version={keyVaultApiVersion}";
        Uri keyVaultCertificateUri = new(keyVaultUri, keyVaultCertificateRelativeUrl);
        if (!keyVaultAuthCtx.ResolveAuthorityAndResourceFromChallengeUri(
            keyVaultCertificateUri,
            out string _,
            out string keyVaultAuthResource
            ))
            keyVaultAuthResource = "https://vault.azure.net";
        AccessToken keyVaultAccessToken = await tokenCredential.GetTokenAsync(
            new([$"{keyVaultAuthResource}/.default"]), default
            ).ConfigureAwait(continueOnCapturedContext: false);
        using HttpClient httpClient = new();
        using HttpRequestMessage httpRequ = new(HttpMethod.Get, keyVaultCertificateUri)
        {
            Headers =
            {
                Authorization = new("Bearer", keyVaultAccessToken.Token),
            }
        };
        using HttpResponseMessage httpResp = await httpClient
            .SendAsync(httpRequ, HttpCompletionOption.ResponseHeadersRead)
            .ConfigureAwait(continueOnCapturedContext: false);
        try { httpResp.EnsureSuccessStatusCode(); }
        catch (HttpRequestException httpExcept)
        {
            var trace = serviceProvider.Get<ITracingService>();
            trace.Trace("Failed to retrieve Azure Key Vault Certificate information: {0}", httpExcept);
            throw new InvalidPluginExecutionException(
                httpStatus: (PluginHttpStatusCode)httpResp.StatusCode,
                message: $"Failed to retrieve Azure Key Vault Certificate information: {httpExcept.Message}"
                );
        }
        using Stream httpRespStream = await httpResp.Content.ReadAsStreamAsync();
        using JsonDocument keyVaultCertificateJson = await JsonDocument
            .ParseAsync(httpRespStream).ConfigureAwait(continueOnCapturedContext: false);
        var keyVaultCertificate = (KeyVaultCertificate)typeof(KeyVaultCertificate).GetConstructor(
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            Type.DefaultBinder,
            types: [typeof(CertificateProperties)],
            modifiers: default
            ).Invoke([null]);
        keyVaultJsonSerializationInterfaceType.InvokeMember(
            "ReadProperties",
            BindingFlags.Instance | BindingFlags.Public |
            BindingFlags.InvokeMethod,
            target: keyVaultCertificate,
            args: [keyVaultCertificateJson.RootElement],
            binder: Type.DefaultBinder,
            culture: System.Globalization.CultureInfo.InvariantCulture
            );
        return keyVaultCertificate;
    }
}