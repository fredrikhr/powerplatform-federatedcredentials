using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.KeyVault;
using Azure.ResourceManager.Resources;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class ResolveKeyVaultReferencePlugin : PluginBase, IPlugin
{
    internal static class InputParameterNames
    {
        internal const string KeyVaultReference = nameof(KeyVaultReference);
        internal const string KeyVaultUri = nameof(KeyVaultUri);
        internal const string KeyVaultObjectType = nameof(KeyVaultObjectType);
        internal const string KeyVaultObjectName = nameof(KeyVaultObjectName);
        internal const string KeyVaultObjectVersion = nameof(KeyVaultObjectVersion);
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
        KeyVaultReference? keyvaultReference;
        string? keyVaultResourceIdString = null;
        string? keyVaultUri;
        keytype keyVaultObjectType = (keytype)(-1);
        if (KeyVaultReference.EntityLogicalName.Equals(context.PrimaryEntityName, cmp))
        {
            keyvaultReference = RetrieveEntityByEntityId(
                serviceProvider,
                context.PrimaryEntityId
                ).ToEntity<KeyVaultReference>();
        }
        else if (context.InputParameters.TryGetValue(
            InputParameterNames.KeyVaultReference,
            out Entity? keyVaultReferenceInputEntity
            ) && keyVaultReferenceInputEntity is not null)
        {
            keyvaultReference = keyVaultReferenceInputEntity
                .ToEntity<KeyVaultReference>();
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
            keyvaultReference = new();
            if (context.InputParameters.TryGetValue(
                InputParameterNames.KeyVaultUri,
                out keyVaultUri
                ))
            {
                keyvaultReference.KeyVaultUri = keyVaultUri;
            }
            if ((context.InputParameters.TryGetValue(
                InputParameterNames.KeyVaultObjectType,
                out OptionSetValue keyVaultObjectTypeOptionSetValue
                ) && keyVaultObjectTypeOptionSetValue
                is { Value: int keyVaultObjectTypeIntValue }) ||
                context.InputParameters.TryGetValue(
                InputParameterNames.KeyVaultObjectType,
                out keyVaultObjectTypeIntValue
                ))
            {
                keyVaultObjectType = (keytype)keyVaultObjectTypeIntValue switch
                {
                    keytype.Secret => keytype.Secret,
                    keytype.Certificate => keytype.Certificate,
                    keytype.CertificateWithX5c => keytype.CertificateWithX5c,
                    _ => throw new InvalidPluginExecutionException(
                        message: $"Invalid input parameter {InputParameterNames.KeyVaultObjectType}: {keyVaultObjectTypeIntValue} is not a valid Key Vault Object Type.",
                        httpStatus: PluginHttpStatusCode.BadRequest
                        ),
                };
                keyvaultReference.KeyType = keyVaultObjectType;
            }
            else if (context.InputParameters.TryGetValue(
                InputParameterNames.KeyVaultObjectType,
                out string keyVaultObjectTypeStringValue
                ) && Enum.TryParse(
                keyVaultObjectTypeStringValue,
                ignoreCase: true,
                out keyVaultObjectType
                ))
            {
                keyvaultReference.KeyType = keyVaultObjectType switch
                {
                    keytype.Secret or
                    keytype.Certificate or
                    keytype.CertificateWithX5c => keyVaultObjectType,
                    _ => throw new InvalidPluginExecutionException(
                        message: $"Invalid input parameter {InputParameterNames.KeyVaultObjectType}: '{keyVaultObjectTypeStringValue}' is not a valid Key Vault Object Type.",
                        httpStatus: PluginHttpStatusCode.BadRequest
                        ),
                };
            }
            if (context.InputParameters.TryGetValue(
                InputParameterNames.KeyVaultObjectName,
                out string keyVaultObjectName
                ) && !string.IsNullOrEmpty(keyVaultObjectName))
            {
                keyvaultReference.KeyName = keyVaultObjectName;
                if (context.InputParameters.TryGetValue(
                    InputParameterNames.KeyVaultObjectVersion,
                    out string? keyVaultObjectVersion
                    ))
                {
                    keyvaultReference[KeyVaultReference.Fields.KeyVersion] =
                        keyVaultObjectVersion;
                }
            }
            if (context.InputParameters.TryGetValue(
                InputParameterNames.KeyVaultResourceIdentifier,
                out keyVaultResourceIdString
                ))
            {
                keyvaultReference[KeyVaultReference.Fields.KeyVaultResourceIdentifier] =
                    keyVaultResourceIdString;
            }
        }

        ResourceIdentifier keyVaultResourceIdentifier;
        if (string.IsNullOrEmpty(keyVaultResourceIdString) &&
            (!keyvaultReference.TryGetAttributeValue(
                KeyVaultReference.Fields.KeyVaultResourceIdentifier,
                out keyVaultResourceIdString
                ) || string.IsNullOrEmpty(keyVaultResourceIdString)))
        {
            keyVaultResourceIdentifier = ResolveKeyVaultResourceIdentifier(
                serviceProvider,
                keyvaultReference
                ).GetAwaiter().GetResult();
            keyvaultReference[KeyVaultReference.Fields.KeyVaultResourceIdentifier] =
                keyVaultResourceIdentifier.ToString();
        }
        else
        {
            keyVaultResourceIdentifier = ResourceIdentifier.Parse(keyVaultResourceIdString!);
        }

        if (string.IsNullOrEmpty(keyvaultReference.KeyVaultUri) &&
            keyVaultResourceIdentifier.Parent?.Name is string keyVaultName)
        {
            keyVaultUri = $"https://{keyVaultName}.vault.azure.net";
            keyvaultReference.KeyVaultUri = keyVaultUri;
        }
        if (string.IsNullOrEmpty(keyvaultReference.KeyName) &&
            keyVaultResourceIdentifier.Name is string keyNameFromId)
        {
            keyvaultReference.KeyName = keyNameFromId;
            keytype keyType = keyVaultResourceIdentifier.ResourceType.GetLastType() switch
            {
                string t when t.EndsWith("certificates", cmp) =>
                    keytype.Certificate,
                string t when t.EndsWith("secrets", cmp) =>
                    keytype.Secret,
                _ => (keytype)(-1),
            };
            keyvaultReference.KeyType ??= keyType;
        }

        context.OutputParameters[OutputParameterNames.KeyVaultReference] =
            keyvaultReference;
        context.OutputParameters[OutputParameterNames.KeyVaultResourceIdentifier] =
            keyvaultReference[KeyVaultReference.Fields.KeyVaultResourceIdentifier];

        static KeyVaultReference RetrieveEntityByEntityId(
            IServiceProvider serviceProvider,
            Guid entityId
            )
        {
            IOrganizationService dataverseService = serviceProvider
                .Get<IOrganizationServiceFactory>()
                .CreateOrganizationService(null);
            return dataverseService.Retrieve(
                KeyVaultReference.EntityLogicalName,
                entityId,
                KeyVaultReference.ColumnSet
                ).ToEntity<KeyVaultReference>();
        }
    }

    private static string GetKeyVaultName(string keyVaultUrl)
    {
        Uri keyVaultUri = new(keyVaultUrl, UriKind.Absolute);
        return keyVaultUri.Host[..keyVaultUri.Host.IndexOf('.')];
    }

    private static async Task<ResourceIdentifier> ResolveKeyVaultResourceIdentifier(
        IServiceProvider serviceProvider,
        KeyVaultReference entity
        )
    {
        const StringComparison cmp = StringComparison.OrdinalIgnoreCase;
        string? keyVaultUrl;
        if (string.IsNullOrEmpty(keyVaultUrl = entity.KeyVaultUri))
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
                        entity
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
        KeyVaultReference entity
        )
    {
        string keyVaultParentId = keyVaultResource.Id.ToString();
        var keyVaultObjectName = entity.KeyName;
        var keyVaultObjectType = entity.KeyType;
        _ = entity.TryGetAttributeValue(
            KeyVaultReference.Fields.KeyVersion,
            out string? keyVaultObjectVersion
            );
        string keyVaultObjectInfix = keyVaultObjectType switch
        {
            keytype.Certificate or
            keytype.CertificateWithX5c => "certificates",
            keytype.Secret => "secrets",
            _ => "*",
        };
        string keyVaultResourceIdString =
            $"{keyVaultParentId}/{keyVaultObjectInfix}/{keyVaultObjectName}";
        if (!string.IsNullOrEmpty(keyVaultObjectVersion))
            keyVaultResourceIdString += $"/{keyVaultObjectVersion}";
        ResourceIdentifier keyVaultResourceId = ResourceIdentifier.Parse(keyVaultResourceIdString);
        return keyVaultResourceId;
    }
}