using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Identity.Client;

using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class KeyVaultCredentialsTokenAcquisitionPlugin
    : FederatedIdentityTokenAcquisitionPlugin, IPlugin
{
    internal static new class OutputParameterNames
    {
        internal const string KeyVaultResourceIdentifier = nameof(KeyVaultResourceIdentifier);
    }

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
        PluginContext pluginContext,
        string tenantId,
        string clientId,
        IEnumerable<string> scopes
        )
    {
        _ = pluginContext ?? throw new ArgumentNullException(nameof(pluginContext));
        IPluginExecutionContext2 context = pluginContext.ExecutionContext;
        ParameterCollection keyVaultAccessEvalOutputs = [];
        EvaluateKeyVaultDataAccessPermissionsPlugin.ExecuteInternal(
            pluginContext,
            keyVaultAccessEvalOutputs
            );
        if (!keyVaultAccessEvalOutputs.TryGetValue(
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
        if (keyVaultReferenceEntity.TryGetAttributeValue(
            KeyVaultReference.Fields.KeyVaultResourceIdentifier,
            out string keyVaultResourceIdentifier
            ))
        {
            pluginContext.Outputs[OutputParameterNames.KeyVaultResourceIdentifier] =
                keyVaultResourceIdentifier;
        }

        ConfidentialClientApplicationBuilder msalBuilder = MsalPluginUtility.CreateMsalAppBuilder(
            pluginContext, tenantId,
            clientId,
            keyVaultUri,
            keyVaultDataType ?? (keytype)(-1),
            keyVaultDataName,
            keyVaultDataVersion,
            out _,
            out _
            );
        IConfidentialClientApplication msalApp = msalBuilder.Build();
        AuthenticationResult msalAuthResult = msalApp
            .AcquireTokenForClient(scopes).ExecuteAsync()
            .GetAwaiter().GetResult();

        return msalAuthResult.AccessToken;
    }
}