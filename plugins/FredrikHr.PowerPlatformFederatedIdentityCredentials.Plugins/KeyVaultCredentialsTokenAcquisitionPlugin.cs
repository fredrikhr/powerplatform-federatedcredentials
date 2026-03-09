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
        string resourceId
        )
    {
        IEnumerable<string> msalScopes = [$"{resourceId}/.default"];
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

        ConfidentialClientApplicationBuilder msalBuilder = MsalPluginUtility.CreateMsalAppBuilder(
            serviceProvider,
            tenantId,
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
            .AcquireTokenForClient(msalScopes).ExecuteAsync()
            .GetAwaiter().GetResult();

        return msalAuthResult.AccessToken;
    }
}