using Microsoft.Identity.Client;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Text;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class GetAuthorizationUrlPlugin() : PluginBase(), IPlugin
{
    private const StringComparison OrdInv = StringComparison.OrdinalIgnoreCase;

    internal static class JwtClaimNames
    {
        internal const string OneTimeRedirectUri = "uri";
    }

    internal static class InputParameterNames
    {
        internal const string LoginHint = nameof(LoginHint);
        internal const string Prompt = nameof(Prompt);
        internal const string Scopes = nameof(Scopes);
        internal const string ResponseMode = nameof(ResponseMode);
        internal const string PkceS256CodeChallenge = nameof(PkceS256CodeChallenge);
        internal const string CommonRedirectUri = nameof(CommonRedirectUri);
        internal const string OneTimeRedirectUri = nameof(OneTimeRedirectUri);
        internal const string IncludeIdToken = nameof(IncludeIdToken);
        internal const string NonceParameter = nameof(NonceParameter);
    }

    internal static class OutputParameterNames
    {
        internal const string AuthorizationRequestUrl = nameof(AuthorizationRequestUrl);
        internal const string NonceParameter = nameof(NonceParameter);
    }

    private static readonly JsonWebTokenHandler JwtHandler = new();

    private static readonly Regex IdTokenResponseTypeRegex = new(
        @"\bid_token\b",
        RegexOptions.IgnoreCase |
        RegexOptions.CultureInvariant
        );

    protected override void ExecuteCore(PluginContext context)
    {
        _ = context ?? throw new ArgumentNullException(nameof(context));
        if (
            context.RequestedManagedIdentity
            is not ManagedIdentity reqManagedIdentity
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: "Requested ManagedIdentity entity is not available."
                );
        }
        if (reqManagedIdentity.TenantId is not Guid reqTenantId || reqTenantId == Guid.Empty)
            reqTenantId = context.ExecutionContext.TenantId;
        string reqTenantString = reqTenantId.ToString();
        Guid? reqAppId = reqManagedIdentity.ApplicationId;
        bool hasReqAppId = (reqAppId ?? Guid.Empty) != Guid.Empty;
        Guid? userAppId = context.UserApplicationId;
        bool hasUserAppId = userAppId.HasValue && userAppId != Guid.Empty;
        if (!hasReqAppId)
        {
            reqAppId = hasUserAppId ? userAppId : throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"User is not an application user, and input parameter '{RetrieveRequestedManagedIdentityPlugin.InputParameterNames.ApplicationId}' was not specified."
                );
        }

        if (context.ResolvedKeyVaultReferenceEntity
            is not KeyVaultReference keyVaultReferenceEntity
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: "KeyVaultReference entity not availble."
                );
        }
        ;
        string keyVaultUri = keyVaultReferenceEntity.KeyVaultUri;
        string keyVaultDataName = keyVaultReferenceEntity.KeyName;
        _ = keyVaultReferenceEntity.TryGetAttributeValue(
            KeyVaultReference.Fields.KeyVersion,
            out string? keyVaultDataVersion
            );
        keytype? keyVaultDataType = keyVaultReferenceEntity.KeyType;
        context.Outputs[ResolveKeyVaultReferencePlugin.OutputParameterNames.KeyVaultResourceIdentifier] =
            keyVaultReferenceEntity.TryGetAttributeValue(
                KeyVaultReference.Fields.KeyVaultResourceIdentifier,
                out string keyVaultResourceIdentifier
                ) && !string.IsNullOrEmpty(keyVaultResourceIdentifier)
            ? keyVaultResourceIdentifier
            : context.ResolvedKeyVaultReferenceResourceId?.ToString();

        ParameterCollection inputs = context.Inputs;
        _ = inputs.TryGetValue(
            InputParameterNames.Scopes,
            out string[] scopes
            );
        if (!inputs.TryGetValue(
            InputParameterNames.OneTimeRedirectUri,
            out string oneTimeRedirectUri) ||
            string.IsNullOrEmpty(oneTimeRedirectUri))
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing or empty required parameter: {InputParameterNames.OneTimeRedirectUri}"
                );
        }
        if (!inputs.TryGetValue(
            InputParameterNames.PkceS256CodeChallenge,
            out string pkceCodeChallenge) ||
            string.IsNullOrEmpty(pkceCodeChallenge)
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing or empty required parameter: {InputParameterNames.PkceS256CodeChallenge}"
                );
        }

        var msalBuilder = MsalPluginUtility.CreateMsalAppBuilder(
            context, reqTenantString,
            reqAppId.ToString(),
            keyVaultUri,
            keyVaultDataType ?? (keytype)(-1),
            keyVaultDataName,
            keyVaultDataVersion,
            out _,
            out EncryptingCredentials keyVaultEncryptCreds
            );

        SecurityTokenDescriptor stateJwtDesc = new()
        {
            Claims = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
            {
                { JwtClaimNames.OneTimeRedirectUri, oneTimeRedirectUri },
            },
            AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase),
            EncryptingCredentials = keyVaultEncryptCreds,
            IncludeKeyIdInHeader = true,
        };
        if (inputs.TryGetValue(
            InputParameterNames.CommonRedirectUri,
            out string? commonRedirectUri) &&
            !string.IsNullOrEmpty(commonRedirectUri))
        {
            msalBuilder = msalBuilder.WithRedirectUri(commonRedirectUri);
        }

        string stateQueryParam = JwtHandler.CreateToken(stateJwtDesc);
        Dictionary<string, string> msalExtraParams = new(StringComparer.OrdinalIgnoreCase)
        {
            { "state", stateQueryParam },
            { "code_challenge", pkceCodeChallenge },
            { "code_challenge_method", "S256" },
        };
        if (inputs.TryGetValue(
            InputParameterNames.ResponseMode,
            out string responseMode) &&
            !string.IsNullOrEmpty(responseMode))
        {
            msalExtraParams["response_mode"] = responseMode;
        }
        if (!inputs.TryGetValue(
            InputParameterNames.IncludeIdToken,
            out bool includeIdToken
            ))
        {
            includeIdToken = false;
        }

        IConfidentialClientApplication msalClient = msalBuilder.Build();
        var msalAuthReqBuilder = msalClient.GetAuthorizationRequestUrl(scopes)
            .WithExtraQueryParameters(msalExtraParams)
            ;
        if (inputs.TryGetValue(
            InputParameterNames.LoginHint,
            out string loginHint) &&
            !string.IsNullOrEmpty(loginHint))
        {
            msalAuthReqBuilder = msalAuthReqBuilder
                .WithLoginHint(loginHint);
        }
        if (inputs.TryGetValue(
            InputParameterNames.Prompt,
            out string promptBehavior) &&
            !string.IsNullOrEmpty(promptBehavior))
        {
            msalAuthReqBuilder =
                "select_account".Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.SelectAccount)
                : "login".Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.ForceLogin)
                : "no_prompt".Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.NoPrompt)
                : "consent".Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.Consent)
                : "attempt_none".Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.Never)
                : "none".Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.Never)
                : "create".Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.Create)
                : msalAuthReqBuilder; // Don't do anything if not recognized.
        }
        Uri msalAuthReqUri = msalAuthReqBuilder
            .ExecuteAsync().GetAwaiter().GetResult();
        if (includeIdToken)
        {
            if (!inputs.TryGetValue(
                InputParameterNames.NonceParameter,
                out string nonceValue
                ))
            {
                using RandomNumberGenerator rng = RandomNumberGenerator.Create();
                byte[] nonceBytes = new byte[64];
                rng.GetBytes(nonceBytes);
                nonceValue = Base64UrlEncoder.Encode(nonceBytes);
            }

            Dictionary<string, string> msalAuthReqUriQuery =
                GetUriQueryParameters(msalAuthReqUri);
            AddResponseTypeIdToken(msalAuthReqUriQuery);
            msalAuthReqUriQuery["nonce"] = nonceValue;
            context.Outputs[OutputParameterNames.NonceParameter] = nonceValue;
            UriBuilder msalAuthReqUriBuilder = new(msalAuthReqUri)
            {
                Query = ToUriQuery(msalAuthReqUriQuery),
            };
            msalAuthReqUri = msalAuthReqUriBuilder.Uri;
        }

        ParameterCollection outputs = context.Outputs;
        outputs[OutputParameterNames.AuthorizationRequestUrl] =
            msalAuthReqUri.ToString();
    }

    private static Dictionary<string, string> GetUriQueryParameters(Uri uri)
    {
        Dictionary<string, string> dict = new(StringComparer.OrdinalIgnoreCase);
        string query = uri.Query;
        for (
            int keyIdx = query.StartsWith("?", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
            keyIdx < query.Length;
            keyIdx++
            )
        {
            int eqIdx = query.IndexOf('=', keyIdx);
            int ampIdx;
            string key;
            string value;
            if (eqIdx < 0)
            {
                key = query[keyIdx..];
                value = string.Empty;
                ampIdx = query.Length;
            }
            else
            {
                key = query[keyIdx..eqIdx];
                int valueIdx = eqIdx + 1;
                ampIdx = query.IndexOf('&', valueIdx);
                if (ampIdx < 0) ampIdx = query.Length;
                value = query[valueIdx..ampIdx];
            }
            (key, value) = (
                Uri.UnescapeDataString(key).Trim(),
                Uri.UnescapeDataString(value).Trim()
                );
            dict[key] = value;
            keyIdx = ampIdx;
        }
        return dict;
    }

    private static void AddResponseTypeIdToken(Dictionary<string, string> query)
    {
        _ = query.TryGetValue("response_type", out string? responseType);
        if (IdTokenResponseTypeRegex.IsMatch(responseType)) return;
        responseType += (string.IsNullOrEmpty(responseType) ? "" : " ") +
            "id_token";
        query["response_type"] = responseType;
    }

    private static string ToUriQuery(Dictionary<string, string> dict)
    {
        return dict.Count == 0
            ? string.Empty
            : string.Join(
                "&",
                dict.Select(static entry =>
                    $"{Uri.EscapeDataString(entry.Key)}={Uri.EscapeDataString(entry.Value)}"
                    )
                );
    }
}