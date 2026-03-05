using System.Security.Cryptography.X509Certificates;

using Microsoft.Identity.Client;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using Azure.Security.KeyVault.Certificates;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class GetAuthorizationUrlPlugin() : PluginBase(), IPlugin
{
    private const StringComparison OrdInv = StringComparison.OrdinalIgnoreCase;

    internal static class JwtClaimNames
    {
        internal const string OneTimeRedirectUri = "uri";
        internal const string KeyVaultUri = "kv_uri";
        internal const string KeyVaultSecretName = "kv_sname";
    }

    internal static class InputParameterNames
    {
        internal const string LoginHint = nameof(LoginHint);
        internal const string Prompt = nameof(Prompt);
        internal const string Scopes = nameof(Scopes);
        internal const string CommonRedirectUrl = nameof(CommonRedirectUrl);
        internal const string OneTimeRedirectUrl = nameof(OneTimeRedirectUrl);
    }

    internal static class OutputParameterNames
    {
        internal const string AuthorizationRequestUrl = nameof(AuthorizationRequestUrl);
        internal const string PkceCodeVerifier = nameof(PkceCodeVerifier);
    }

    private static readonly JsonWebTokenHandler JwtHandler =  new();

    protected override void ExecuteCore(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.Get<IPluginExecutionContext6>();
        ParameterCollection inputs = context.InputParameters;
        var authorityInfo = serviceProvider.Get<IEnvironmentService>();
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
        ResolveKeyVaultReferencePlugin.ExecuteInternal(serviceProvider);

        var keyVaultReferenceEntity = context.OutputParameters[
            ResolveKeyVaultReferencePlugin.OutputParameterNames.KeyVaultReference
            ] switch
        {
            KeyVaultReference e => e,
            Entity e => e.ToEntity<KeyVaultReference>(),
            _ => throw new InvalidPluginExecutionException("KeyVaultReference entity not availble."),
        };
        string keyVaultUri = keyVaultReferenceEntity.KeyVaultUri;
        string keyVaultDataName = keyVaultReferenceEntity.KeyName;
        _ = keyVaultReferenceEntity.TryGetAttributeValue(
            KeyVaultReference.Fields.KeyVersion,
            out string? keyVaultDataVersion
            );
        keytype? keyVaultDataType = keyVaultReferenceEntity.KeyType;

        string[] scopes = context.InputParameterOrDefault<string[]>(
            InputParameterNames.Scopes
            );
        if (!inputs.TryGetValue(
            InputParameterNames.OneTimeRedirectUrl,
            out string oneTimeRedirectUrl) ||
            string.IsNullOrEmpty(oneTimeRedirectUrl))
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: ""
                );
        }

        var msalBuilder = MsalPluginUtility.CreateMsalAppBuilder(
            serviceProvider,
            reqTenantString,
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
                { JwtClaimNames.OneTimeRedirectUri, oneTimeRedirectUrl },
            },
            AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase),
            EncryptingCredentials = keyVaultEncryptCreds,
        };
        switch (keyVaultDataType)
        {
            case keytype.Secret:
                stateJwtDesc.AdditionalHeaderClaims[JwtClaimNames.KeyVaultUri] =
                    keyVaultUri;
                stateJwtDesc.AdditionalHeaderClaims[JwtClaimNames.KeyVaultSecretName] =
                    keyVaultDataName;
                break;
            case keytype.Certificate:
            case keytype.CertificateWithX5c:
                stateJwtDesc.IncludeKeyIdInHeader = true;
                break;
        }
        if (inputs.TryGetValue(
            InputParameterNames.CommonRedirectUrl,
            out string? commonRedirectUrl) &&
            !string.IsNullOrEmpty(commonRedirectUrl))
        {
            msalBuilder = msalBuilder.WithRedirectUri(commonRedirectUrl);
        }

        string stateQueryParam = JwtHandler.CreateToken(stateJwtDesc);
        Dictionary<string, string> msalExtraParams = new(StringComparer.OrdinalIgnoreCase)
        {
            { "state", stateQueryParam },
            { "response_mode", "form_post" },
        };

        IConfidentialClientApplication msalClient = msalBuilder.Build();
        var msalAuthReqBuilder = msalClient.GetAuthorizationRequestUrl(scopes)
            .WithPkce(out string msalPkceVerifier)
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
                nameof(Prompt.SelectAccount).Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.SelectAccount)
                : nameof(Prompt.ForceLogin).Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.ForceLogin)
                : nameof(Prompt.NoPrompt).Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.NoPrompt)
                : nameof(Prompt.Consent).Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.Consent)
                : nameof(Prompt.Never).Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.Never)
                : nameof(Prompt.Create).Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.Create)
                : msalAuthReqBuilder; // Don't do anything if not recognized.
        }
        Uri msalAuthReqUri = msalAuthReqBuilder
            .ExecuteAsync().GetAwaiter().GetResult();

        ParameterCollection outputs = context.OutputParameters;
        outputs[OutputParameterNames.AuthorizationRequestUrl] =
            msalAuthReqUri.ToString();
        outputs[OutputParameterNames.PkceCodeVerifier] = msalPkceVerifier;
    }
}