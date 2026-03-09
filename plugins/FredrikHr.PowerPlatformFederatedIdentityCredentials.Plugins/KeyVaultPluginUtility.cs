using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using System.Security.Cryptography.X509Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Identity.Client;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

internal static class KeyVaultPluginUtility
{
    private static readonly UTF8Encoding Utf8Encoding =
        new(encoderShouldEmitUTF8Identifier: false);

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Security",
        "CA5379: Ensure Key Derivation Function algorithm is sufficiently strong",
        Justification = ".NET Framework"
        )]
    internal static SymmetricSecurityKey GetKeyVaultSecretSecurityKey(
        string keyVaultUri,
        string keyVaultSecretName,
        string keyVaultSecretValue,
        int keySizeBits
        )
    {
        byte[] keyDerivationSalt = Utf8Encoding.GetBytes(new Uri(
            baseUri: new Uri(keyVaultUri, UriKind.Absolute),
            $"/secrets/{Uri.EscapeUriString(keyVaultSecretName)}"
            ).ToString());
        const int bitsPerByte = 8;
        using Rfc2898DeriveBytes keyDerivationAlg = new(
            password: keyVaultSecretValue,
            salt: keyDerivationSalt,
            iterations: 100_000
            );
        byte[] keyBytes = keyDerivationAlg.GetBytes(keySizeBits / bitsPerByte);
        SymmetricSecurityKey jweKey = new(keyBytes);
        return jweKey;
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability",
        "CA2000: Dispose objects before losing scope",
        Justification = nameof(X509SecurityKey)
        )]
    internal static X509SecurityKey GetKeyVaultPublicX509SecurityKey(
        KeyVaultCertificate keyVaultCertificate
        )
    {
        X509Certificate2 x509Certificate = new(keyVaultCertificate.Cer);
        return new(x509Certificate, keyVaultCertificate.Id.ToString());
    }

    internal static async Task<(KeyVaultCertificate certInfo, RsaSecurityKey rsaKey)> GetKeyVaultPrivateRsaSecurityKeyAsync(
        IServiceProvider serviceProvider,
        string keyVaultUrl,
        string keyVaultCertificateName,
        string? keyVaultCertificateVersion = null
        )
    {
        KeyVaultCertificate keyVaultCertificateInfo = await GetKeyVaultCertificateAsync(
            serviceProvider,
            keyVaultUrl,
            keyVaultCertificateName,
            keyVaultCertificateVersion
            ).ConfigureAwait(continueOnCapturedContext: false);
        RsaSecurityKey keyVaultRsaKey = await GetKeyVaultPrivateRsaSecurityKeyAsync(
            serviceProvider,
            keyVaultCertificateInfo
            );
        return (keyVaultCertificateInfo, keyVaultRsaKey);
    }

    internal static async Task<(KeyVaultCertificate certInfo, RsaSecurityKey rsaKey)> GetKeyVaultPrivateRsaSecurityKeyAsync(
        IServiceProvider serviceProvider,
        Uri keyVaultCertificateUri
        )
    {
        KeyVaultCertificate keyVaultCertificateInfo = await GetKeyVaultCertificateAsync(
            serviceProvider,
            keyVaultCertificateUri
            ).ConfigureAwait(continueOnCapturedContext: false);
        RsaSecurityKey keyVaultRsaKey = await GetKeyVaultPrivateRsaSecurityKeyAsync(
            serviceProvider,
            keyVaultCertificateInfo
            );
        return (keyVaultCertificateInfo, keyVaultRsaKey);
    }

    internal static async Task<RsaSecurityKey> GetKeyVaultPrivateRsaSecurityKeyAsync(
        IServiceProvider serviceProvider,
        KeyVaultCertificate keyVaultCertificateInfo
        )
    {
        TokenCredential tokenCredential = AzureResourceContextProvider
            .GetOrCreateTokenCredential(serviceProvider);
        CryptographyClientOptions keyVaultCryptoClientOptions = new();
        KeyResolver keyVaultKeyResolver = new(tokenCredential, keyVaultCryptoClientOptions);
        CryptographyClient keyVaultCryptoClient = await keyVaultKeyResolver
            .ResolveAsync(keyVaultCertificateInfo.KeyId)
            .ConfigureAwait(continueOnCapturedContext: false);
        RSAKeyVault keyVaultRsaKey = await keyVaultCryptoClient
            .CreateRSAAsync()
            .ConfigureAwait(continueOnCapturedContext: false);
        RsaSecurityKey keyVaultRsaSecKey = new(keyVaultRsaKey);
        return keyVaultRsaSecKey;
    }

    internal static Task<KeyVaultCertificate> GetKeyVaultCertificateAsync(
        IServiceProvider serviceProvider,
        string keyVaultUrl,
        string keyVaultCertificateName,
        string? keyVaultCertificateVersion = null
        )
    {
        Uri keyVaultUri = new(keyVaultUrl, UriKind.Absolute);
        string keyVaultCertificateRelativeUrl = string.IsNullOrWhiteSpace(keyVaultCertificateVersion)
            ? $"/certificates/{Uri.EscapeUriString(keyVaultCertificateName)}"
            : $"/certificates/{Uri.EscapeUriString(keyVaultCertificateName)}/{Uri.EscapeUriString(keyVaultCertificateVersion)}";
        Uri keyVaultCertificateUri = new(keyVaultUri, keyVaultCertificateRelativeUrl);
        return GetKeyVaultCertificateAsync(
            serviceProvider,
            keyVaultCertificateUri
            );
    }

    // Loading and using CertificateClient from assembly hosted in plugin sandbox worker environment
    // fails, retrieve KeyVaultCertificate resource manually using HTTP-client instead.
    internal static async Task<KeyVaultCertificate> GetKeyVaultCertificateAsync(
        IServiceProvider serviceProvider,
        Uri keyVaultCertificateUri
        )
    {
        Type keyVaultJsonSerializationInterfaceType = Type.GetType(
            "Azure.Security.KeyVault.IJsonDeserializable, Azure.Security.KeyVault.Certificates, PublicKeyToken=92742159e12e44c8",
            throwOnError: true, ignoreCase: true
            );
        var keyVaultAuthCtx = serviceProvider.Get<IAssemblyAuthenticationContext2>();
        TokenCredential tokenCredential = AzureResourceContextProvider
            .GetOrCreateTokenCredential(serviceProvider);

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
        string keyVaultApiVersionQuery = $"?api-version={keyVaultApiVersion}";
        keyVaultCertificateUri = new(keyVaultCertificateUri, keyVaultApiVersionQuery);
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

    internal static Func<AssertionRequestOptions, Task<string>> GetKeyVaultCertificateAssertionProvider(
        IServiceProvider serviceProvider,
        string keyVaultUrl,
        string keyVaultCertificateName,
        string? keyVaultCertificateVersion = null,
        string? assertionJwtAlgorithm = null,
        bool sendX5c = false
        )
    {
        Task<(KeyVaultCertificate info, SigningCredentials signCreds, string assertionHeaderEncoded)> keyVaultCertificateStaticTask =
            GetClientAssertionStaticData(
                serviceProvider,
                keyVaultUrl,
                keyVaultCertificateName,
                keyVaultCertificateVersion,
                assertionJwtAlgorithm,
                sendX5c
            );

        return GetClientAssertion;

        async Task<string> GetClientAssertion(AssertionRequestOptions context)
        {
            var (info, signCreds, assertionHeaderEncoded) = await keyVaultCertificateStaticTask
                .ConfigureAwait(continueOnCapturedContext: false);
            DateTime assertionIssuedAt = DateTime.UtcNow;
            System.IdentityModel.Tokens.Jwt.JwtPayload assertionPayload = new(
                issuer: context.ClientID,
                audience: context.TokenEndpoint,
                notBefore: assertionIssuedAt,
                expires: assertionIssuedAt.AddMinutes(2),
                issuedAt: assertionIssuedAt,
                claims: [
                    new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new(JwtRegisteredClaimNames.Sub, context.ClientID),
                ]);
            string assertionSignInput = $"{assertionHeaderEncoded}.{assertionPayload.Base64UrlEncode()}";
            string assertionSignature = JwtTokenUtilities.CreateEncodedSignature(
                assertionSignInput,
                signCreds
                );
            return $"{assertionSignInput}.{assertionSignature}";
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage(
            "Security",
            "CA5350: Do Not Use Weak Cryptographic Algorithms",
            Justification = nameof(X509Certificate2)
            )]
        static async Task<(KeyVaultCertificate info, SigningCredentials signCreds, string assertionHeaderEncoded)> GetClientAssertionStaticData(
            IServiceProvider serviceProvider,
            string keyVaultUrl,
            string keyVaultCertificateName,
            string? keyVaultCertificateVersion = null,
            string? assertionJwtAlgorithm = null,
            bool sendX5c = false
            )
        {
            TokenCredential tokenCredential = AzureResourceContextProvider
                .GetOrCreateTokenCredential(serviceProvider);
            KeyVaultCertificate keyVaultCertificateInfo = await GetKeyVaultCertificateAsync(
                serviceProvider,
                keyVaultUrl,
                keyVaultCertificateName,
                keyVaultCertificateVersion
                ).ConfigureAwait(continueOnCapturedContext: false);
            Task<RsaSecurityKey> keyVaultRsaKeyTask = GetKeyVaultPrivateRsaSecurityKeyAsync(
                serviceProvider,
                keyVaultCertificateInfo
                );
            using var sha1 = SHA1.Create();
            string keyVaultCertificateThumbprint = Base64UrlEncoder.Encode(
                sha1.ComputeHash(keyVaultCertificateInfo.Cer)
                );
            using var sha256 = SHA256.Create();
            string keyVaultCertificateThumbprintS256 = Base64UrlEncoder.Encode(
                sha256.ComputeHash(keyVaultCertificateInfo.Cer)
                );
            RsaSecurityKey keyVaultRsaKey = await keyVaultRsaKeyTask
                .ConfigureAwait(continueOnCapturedContext: false);
            SigningCredentials keyVaultSignCreds = new(
                keyVaultRsaKey,
                assertionJwtAlgorithm ?? SecurityAlgorithms.RsaSsaPssSha256
                );
            System.IdentityModel.Tokens.Jwt.JwtHeader assertionHeader = new(keyVaultSignCreds)
            {
                { JwtHeaderParameterNames.X5t, keyVaultCertificateThumbprint },
                { $"{JwtHeaderParameterNames.X5t}#S256", keyVaultCertificateThumbprintS256 },
            };
            if (sendX5c)
            {
                assertionHeader[JwtHeaderParameterNames.X5c] = Base64UrlEncoder
                    .Encode(keyVaultCertificateInfo.Cer);
            }
            return (
                keyVaultCertificateInfo,
                keyVaultSignCreds,
                assertionHeader.Base64UrlEncode()
                );
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
            "Security",
            "CA5350: Do Not Use Weak Cryptographic Algorithms",
            Justification = nameof(X509Certificate2)
            )]
    internal static Func<AssertionRequestOptions, Task<string>> GetKeyVaultCertificateAssertionProvider(
        KeyVaultCertificate keyVaultCertificateInfo,
        RsaSecurityKey keyVaultRsaKey,
        bool sendX5c = false
        )
    {
        using var sha1 = SHA1.Create();
        string keyVaultCertificateThumbprint = Base64UrlEncoder.Encode(
            sha1.ComputeHash(keyVaultCertificateInfo.Cer)
            );
        using var sha256 = SHA256.Create();
        string keyVaultCertificateThumbprintS256 = Base64UrlEncoder.Encode(
            sha256.ComputeHash(keyVaultCertificateInfo.Cer)
            );
        SigningCredentials keyVaultSignCreds = new(
            keyVaultRsaKey,
            SecurityAlgorithms.RsaSsaPssSha256
            );
        System.IdentityModel.Tokens.Jwt.JwtHeader assertionHeader = new(keyVaultSignCreds)
        {
            { JwtHeaderParameterNames.X5t, keyVaultCertificateThumbprint },
            { $"{JwtHeaderParameterNames.X5t}#S256", keyVaultCertificateThumbprintS256 },
        };
        if (sendX5c)
        {
            assertionHeader[JwtHeaderParameterNames.X5c] = Base64UrlEncoder
                .Encode(keyVaultCertificateInfo.Cer);
        }
        string assertionHeaderEncoded = assertionHeader.Base64UrlEncode();

        return GetClientAssertion;

        Task<string> GetClientAssertion(AssertionRequestOptions context)
        {
            DateTime assertionIssuedAt = DateTime.UtcNow;
            System.IdentityModel.Tokens.Jwt.JwtPayload assertionPayload = new(
                issuer: context.ClientID,
                audience: context.TokenEndpoint,
                notBefore: assertionIssuedAt,
                expires: assertionIssuedAt.AddMinutes(2),
                issuedAt: assertionIssuedAt,
                claims: [
                    new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new(JwtRegisteredClaimNames.Sub, context.ClientID),
                ]);
            string assertionSignInput = $"{assertionHeaderEncoded}.{assertionPayload.Base64UrlEncode()}";
            string assertionSignature = JwtTokenUtilities.CreateEncodedSignature(
                assertionSignInput,
                keyVaultSignCreds
                );
            return Task.FromResult($"{assertionSignInput}.{assertionSignature}");
        }
    }
}