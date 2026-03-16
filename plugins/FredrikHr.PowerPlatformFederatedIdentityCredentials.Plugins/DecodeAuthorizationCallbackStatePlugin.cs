using Azure.Core;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Secrets;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class DecodeAuthorizationCallbackStatePlugin()
    : PluginBase(), IPlugin
{
    private const StringComparison OrdInv = StringComparison.OrdinalIgnoreCase;
    private readonly JsonWebTokenHandler _jwtHandler = new();

    internal static class InputParameterNames
    {
        internal const string State = nameof(State);
    }

    internal static class OutputParameterNames
    {
        internal const string OneTimeRedirectUrl = nameof(OneTimeRedirectUrl);
    }

    protected override void ExecuteCore(PluginContext context)
    {
        _ = context ?? throw new ArgumentNullException(nameof(context));
        ParameterCollection inputs = context.Inputs;
        ParameterCollection outputs = context.Outputs;

        if (!inputs.TryGetValue(
            InputParameterNames.State,
            out string stateJwtEncodedText) ||
            string.IsNullOrEmpty(stateJwtEncodedText))
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing or empty required parameter: {InputParameterNames.State}"
                );
        }

        JsonWebToken stateJwt;
        try
        {
            stateJwt = _jwtHandler.ReadJsonWebToken(stateJwtEncodedText);
        }
        catch (Exception jwtjweReadExcept)
        {
            context.ServiceProvider.Get<ITracingService>()?.Trace(
                "While reading state parameter as JWT: {0}",
                jwtjweReadExcept
                );
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Unable to read provided parameter '{InputParameterNames.State}' as a JWT in compact serialization format: {jwtjweReadExcept.Message}"
                );
        }
        if (!stateJwt.IsEncrypted)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Specified parameter '{InputParameterNames.State}' is not an encrpted JSON Web Token."
                );
        }
        TokenValidationResult stateJwtValidateResult = _jwtHandler
            .ValidateTokenAsync(stateJwt, new()
            {
                ValidAlgorithms = [
                    SecurityAlgorithms.RsaOAEP,
                    SecurityAlgorithms.Aes128CbcHmacSha256
                ],
            })
            .GetAwaiter().GetResult();
        if (!stateJwtValidateResult.IsValid)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Invalid JWE specified in parameter '{InputParameterNames.State}': {stateJwtValidateResult.Exception?.Message}"
                );
        }

        SecurityKey stateJweSecurityKey;
        if (JwtConstants.DirectKeyUseAlg.Equals(stateJwt.Alg, OrdInv))
        {
            if (string.IsNullOrEmpty(stateJwt.Kid))
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Missing Key Vault claims in JWE header in parameter '{InputParameterNames.State}'"
                    );
            }

            Uri keyVaultSecretUri = new(stateJwt.Kid, UriKind.Absolute);
            KeyVaultSecret keyVaultSecretData = KeyVaultPluginUtility.GetKeyVaultSecretAsync(
                context,
                keyVaultSecretUri
                ).GetAwaiter().GetResult();
            stateJweSecurityKey =
                SecurityAlgorithms.Aes128CbcHmacSha256.Equals(stateJwt.Enc, OrdInv)
                ? (SecurityKey)KeyVaultPluginUtility
                    .GetKeyVaultSecretSecurityKey(
                        keyVaultSecretData,
                        keySizeBits: 256
                        )
                : throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Invalid content encryption algorithm in JWE header in parameter '{InputParameterNames.State}': {stateJwt.Enc}"
                    );
        }
        else if (SecurityAlgorithms.RsaOAEP.Equals(stateJwt.Alg, OrdInv))
        {
            string keyVaultRsaKeyId = stateJwt.Kid;
            TokenCredential keyVaultTokenCreds = context.AzureTokenCredential;
            CryptographyClientOptions keyVaultCryptoClientOptions = new();
            KeyResolver keyVaultKeyResolver = new(keyVaultTokenCreds, keyVaultCryptoClientOptions);
            CryptographyClient keyVaultCryptoClient = keyVaultKeyResolver
                .Resolve(new(keyVaultRsaKeyId, UriKind.Absolute));
            RSAKeyVault keyVaultRsaKey = keyVaultCryptoClient.CreateRSA();
            stateJweSecurityKey = new RsaSecurityKey(keyVaultRsaKey)
            { KeyId = keyVaultRsaKey.KeyId };
        }
        else
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Invalid token encryption algorithm in JWE header in parameter '{InputParameterNames.State}': {stateJwt.Alg}"
                );
        }

        try
        {
            stateJwtEncodedText = _jwtHandler.DecryptToken(stateJwt, new()
            {
                TokenDecryptionKey = stateJweSecurityKey,
            });
        }
        catch (Exception jweDecryptExcept)
        {
            context.ServiceProvider.Get<ITracingService>()?.Trace(
                "While decrypting JWE: {0}",
                jweDecryptExcept
                );
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Unable to decrypt JWE specified in parameter '{InputParameterNames.State}': {jweDecryptExcept.Message}"
                );
        }
        try
        {
            stateJwt = _jwtHandler.ReadJsonWebToken(stateJwtEncodedText);
        }
        catch (Exception jwtReadExcept)
        {
            context.ServiceProvider.Get<ITracingService>()?.Trace(
                "While reading decrypted JWT: {0}",
                jwtReadExcept
                );
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Unable to read decrypted payload as JWT specified in parameter '{InputParameterNames.State}': {jwtReadExcept.Message}"
                );
        }
        stateJwtValidateResult = _jwtHandler.ValidateTokenAsync(stateJwt, new()
        {
            RequireSignedTokens = false,
            ValidateLifetime = true,
        }).GetAwaiter().GetResult();
        if (!stateJwtValidateResult.IsValid)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Invalid embedded JWT specified in parameter '{InputParameterNames.State}': {stateJwtValidateResult.Exception?.Message}"
                );
        }
        if (!stateJwt.TryGetValue(
            GetAuthorizationUrlPlugin.JwtClaimNames.OneTimeRedirectUri,
            out string oneTimeRedirectUri) ||
            string.IsNullOrEmpty(oneTimeRedirectUri)
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Embedded JWT specified in parameter '{InputParameterNames.State}' is missing required claim: {GetAuthorizationUrlPlugin.JwtClaimNames.OneTimeRedirectUri}"
                );
        }

        outputs[OutputParameterNames.OneTimeRedirectUrl] = oneTimeRedirectUri;
    }
}