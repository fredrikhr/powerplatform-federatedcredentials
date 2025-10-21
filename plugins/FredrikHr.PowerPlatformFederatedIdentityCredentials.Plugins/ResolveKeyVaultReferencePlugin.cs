using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.KeyVault;
using Azure.ResourceManager.Resources;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.EntityInfo;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class ResolveKeyVaultReferencePlugin : PluginBase, IPlugin
{
    internal static class InputParameterNames
    {
        internal const string KeyVaultReference = nameof(KeyVaultReference);
        internal const string KeyVaultUri = nameof(KeyVaultUri);
        internal const string KeyVaultSecretName = nameof(KeyVaultSecretName);
        internal const string KeyVaultCertificateName = nameof(KeyVaultCertificateName);
        internal const string KeyVaultResourceIdentifier = nameof(KeyVaultResourceIdentifier);
    }

    internal static class OutputParameterNames
    {
        internal const string KeyVaultReference = nameof(KeyVaultReference);
        internal const string KeyVaultResourceIdentifier = nameof(KeyVaultResourceIdentifier);
    }

    protected override void ExecuteCore(IServiceProvider serviceProvider)
    {
        ExecuteInternal(serviceProvider);
    }

    internal static void ExecuteInternal(IServiceProvider serviceProvider)
    {
        const StringComparison cmp = StringComparison.OrdinalIgnoreCase;
        var context = serviceProvider.Get<IPluginExecutionContext>();
        Entity? keyvaultReference;
        string? keyVaultResourceIdString = null;
        string? keyVaultUri;
        if (KeyVaultReferenceEntityInfo.EntityLogicalName.Equals(context.PrimaryEntityName, cmp))
        {
            keyvaultReference = RetrieveEntityByEntityId(
                serviceProvider,
                context.PrimaryEntityId
                );
        }
        else if (context.InputParameters.TryGetValue(
            InputParameterNames.KeyVaultReference,
            out Entity? keyVaultReferenceInputEntity
            ) && keyVaultReferenceInputEntity is not null)
        {
            keyvaultReference = keyVaultReferenceInputEntity;
        }
        else if (context.InputParameters.TryGetValue(
            InputParameterNames.KeyVaultReference,
            out EntityReference keyVaultReferenceEntityReference
            ))
        {
            keyvaultReference = RetrieveEntityByEntityId(
                serviceProvider,
                keyVaultReferenceEntityReference.Id
                );
        }
        else
        {
            keyvaultReference = new(KeyVaultReferenceEntityInfo.EntityLogicalName);
            if (context.InputParameters.TryGetValue(
                InputParameterNames.KeyVaultUri,
                out keyVaultUri
                ))
            {
                keyvaultReference[KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyVaultUri] =
                    keyVaultUri;
            }
            if (context.InputParameters.TryGetValue(
                InputParameterNames.KeyVaultSecretName,
                out string keyVaultSecretName
                ))
            {
                keyvaultReference[KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyName] =
                    keyVaultSecretName;
                keyvaultReference[KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyType] =
                    new OptionSetValue((int)KeyVaultReferenceKeyTypeOptionSet.Secret);
            }
            if (context.InputParameters.TryGetValue(
                InputParameterNames.KeyVaultCertificateName,
                out string keyVaultCertificateName
                ))
            {
                keyvaultReference[KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyName] =
                    keyVaultCertificateName;
                keyvaultReference[KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyType] =
                    new OptionSetValue((int)KeyVaultReferenceKeyTypeOptionSet.Certificate);
            }
            if (context.InputParameters.TryGetValue(
                InputParameterNames.KeyVaultResourceIdentifier,
                out keyVaultResourceIdString
                ))
            {
                keyvaultReference[KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyVaultResourceIdentifier] =
                    keyVaultResourceIdString;
            }
        }

        ResourceIdentifier keyVaultResourceIdentifier;
        if (string.IsNullOrEmpty(keyVaultResourceIdString) &&
            (!keyvaultReference.TryGetAttributeValue(
                KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyVaultResourceIdentifier,
                out keyVaultResourceIdString
                ) || string.IsNullOrEmpty(keyVaultResourceIdString)))
        {
            keyVaultResourceIdentifier = ResolveKeyVaultResourceIdentifier(
                serviceProvider,
                keyvaultReference
                ).GetAwaiter().GetResult();
            keyvaultReference[KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyVaultResourceIdentifier] =
                keyVaultResourceIdentifier.ToString();
        }
        else
        {
            keyVaultResourceIdentifier = ResourceIdentifier.Parse(keyVaultResourceIdString!);
        }

        if ((!keyvaultReference.TryGetAttributeValue(
            KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyVaultUri,
            out keyVaultUri) || string.IsNullOrEmpty(keyVaultUri)) &&
            keyVaultResourceIdentifier.Parent?.Name is string keyVaultName)
        {
            keyVaultUri = $"https://{keyVaultName}.vault.azure.net";
            keyvaultReference[KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyVaultUri] =
                keyVaultUri;
        }
        if ((!keyvaultReference.TryGetAttributeValue(
            KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyName,
            out string keyName) || string.IsNullOrEmpty(keyName)) &&
            keyVaultResourceIdentifier.Name is string keyNameFromId)
        {
            keyvaultReference[KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyName] =
                keyNameFromId;
            OptionSetValue keyType = keyVaultResourceIdentifier.ResourceType.GetLastType() switch
            {
                string t when t.EndsWith("certificates", cmp) =>
                    new((int)KeyVaultReferenceKeyTypeOptionSet.Certificate),
                string t when t.EndsWith("secrets", cmp) =>
                    new((int)KeyVaultReferenceKeyTypeOptionSet.Secret),
                _ => new((int)KeyVaultReferenceKeyTypeOptionSet.Unknown),
            };
            keyvaultReference[KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyType] =
                keyType;
        }

        context.OutputParameters[OutputParameterNames.KeyVaultReference] =
            keyvaultReference;
        context.OutputParameters[OutputParameterNames.KeyVaultResourceIdentifier] =
            keyvaultReference[KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyVaultResourceIdentifier];

        static Entity RetrieveEntityByEntityId(
            IServiceProvider serviceProvider,
            Guid entityId
            )
        {
            IOrganizationService dataverseService = serviceProvider
                .Get<IOrganizationServiceFactory>()
                .CreateOrganizationService(null);
            return dataverseService.Retrieve(
                KeyVaultReferenceEntityInfo.EntityLogicalName,
                entityId,
                KeyVaultReferenceEntityInfo.ColumnSet
                );
        }
    }

    private static string GetKeyVaultName(string keyVaultUrl)
    {
        Uri keyVaultUri = new(keyVaultUrl, UriKind.Absolute);
        return keyVaultUri.Host[..keyVaultUri.Host.IndexOf('.')];
    }

    private static async Task<ResourceIdentifier> ResolveKeyVaultResourceIdentifier(
        IServiceProvider serviceProvider,
        Entity keyVaultReferenceEntity
        )
    {
        const StringComparison cmp = StringComparison.OrdinalIgnoreCase;
        if (!keyVaultReferenceEntity.TryGetAttributeValue(
            KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyVaultUri,
            out string? keyVaultUrl) || string.IsNullOrEmpty(keyVaultUrl))
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: "Unable to resolve Key Vault Resource without Key Vault URI."
                );
        }
        string keyVaultName = GetKeyVaultName(keyVaultUrl!);
        ArmClient armClient = AzureResourceContextProvider.GetOrCreateArmClient(
            serviceProvider
            );
        await foreach (SubscriptionResource subscription in armClient
            .GetSubscriptions().ConfigureAwait(continueOnCapturedContext: false))
        {
            await foreach (KeyVaultResource keyVaultResource in subscription
                .GetKeyVaultsAsync().ConfigureAwait(continueOnCapturedContext: false))
            {
                if (keyVaultResource.Data.Name.Equals(keyVaultName, cmp))
                {
                    ResourceIdentifier resourceIdentifier = ResolveKeyVaultResourceIdentifier(
                        keyVaultResource,
                        keyVaultReferenceEntity
                        );
                    return resourceIdentifier;
                }
            }
        }

        throw new InvalidPluginExecutionException(
            httpStatus: PluginHttpStatusCode.NotFound,
            message: $"No Key Vault named '{keyVaultName}' (inferred from URI '{keyVaultUrl}') could be found."
            );
    }

    private static ResourceIdentifier ResolveKeyVaultResourceIdentifier(
        KeyVaultResource keyVaultResource,
        Entity keyVaultReferenceEntity
        )
    {
        string keyVaultParentId = keyVaultResource.Id.ToString();
        var keyVaultObjectName = (string)
            keyVaultReferenceEntity[KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyName];
        var keyVaultObjectTypeValue = (OptionSetValue)
            keyVaultReferenceEntity[KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyType];
        var keyVaultObjectType = (KeyVaultReferenceKeyTypeOptionSet)
            keyVaultObjectTypeValue.Value;
        string keyVaultObjectInfix = keyVaultObjectType switch
        {
            KeyVaultReferenceKeyTypeOptionSet.Certificate or
            KeyVaultReferenceKeyTypeOptionSet.CertificateWithX5c => "certificates",
            KeyVaultReferenceKeyTypeOptionSet.Secret => "secrets",
            _ => "*",
        };
        string keyVaultResourceIdString = $"{keyVaultParentId}/{keyVaultObjectInfix}/{keyVaultObjectName}";
        ResourceIdentifier keyVaultResourceId = ResourceIdentifier.Parse(keyVaultResourceIdString);
        return keyVaultResourceId;
    }
}