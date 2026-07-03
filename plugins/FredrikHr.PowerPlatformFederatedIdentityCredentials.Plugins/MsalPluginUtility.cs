using Azure.Security.KeyVault.Secrets;

using Microsoft.Identity.Client;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

internal static class MsalPluginUtility
{
    internal static ConfidentialClientApplicationBuilder CreateMsalClientBuilder(
        ConfidentialClientApplicationOptions options,
        PluginExecutionInformation executionInformation
        )
    {
        var builder = ConfidentialClientApplicationBuilder
            .CreateWithApplicationOptions(options);

        if (executionInformation.ClientCredentialsSource
            is PluginClientCredentialsSource credentialsSource)
        {
            string? customKeyIdentifier = credentialsSource.CustomKeyIdentifier;
            bool sendX5c = false;
            switch (credentialsSource.KeyVaultObjectType)
            {
                case keytype.Secret:
                    KeyVaultSecretIdentifier keyVaultSecretIdentifier =
                        credentialsSource.KeyVaultSecretIdentifier
                        ?? throw new InvalidOperationException("KeyVaultSecretIdentifier is null");
                    SecretClient keyVaultSecretClient = new(
                        keyVaultSecretIdentifier.VaultUri,
                        executionInformation.PluginAzureTokenCredential
                        );
                    KeyVaultSecret keyVaultSecret = keyVaultSecretClient
                        .GetSecret(
                            keyVaultSecretIdentifier.Name,
                            keyVaultSecretIdentifier.Version
                            );
                    builder = builder.WithClientSecret(keyVaultSecret.Value);
                    break;
                case keytype.Certificate:
                    var clientAssertionProvider = KeyVaultPluginUtility
                        .GetKeyVaultCertificateAssertionProvider(
                            executionInformation.PluginAzureTokenCredential,
                            credentialsSource.KeyVaultCertificateIdentifier
                            ?? throw new InvalidOperationException("KeyVaultCertificateIdentifier is null"),
                            customKeyIdentifier,
                            sendX5c: sendX5c
                            );
                    builder = builder.WithClientAssertion(clientAssertionProvider);
                    break;
                case keytype.CertificateWithX5c:
                    sendX5c = true;
                    goto case keytype.Certificate;
            }
        }

        return builder;
    }
}
