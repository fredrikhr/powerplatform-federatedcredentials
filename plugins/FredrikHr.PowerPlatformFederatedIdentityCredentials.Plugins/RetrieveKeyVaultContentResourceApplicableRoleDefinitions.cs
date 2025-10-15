using System.Text.RegularExpressions;

using Azure;
using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.Authorization;
using Azure.ResourceManager.Authorization.Models;
using Azure.ResourceManager.Resources;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.EntityInfo;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class RetrieveKeyVaultContentResourceApplicableRoleDefinitions()
    : PluginBase(ExecuteInternal), IPlugin
{
    internal static class InputParameterNames
    {
        internal const string KeyVaultReference = nameof(KeyVaultReference);
    }

    internal static class OutputParameterNames
    {
        internal const string KeyVaultReference = nameof(KeyVaultReference);
        internal const string RolesAllowGetSecretValue = nameof(RolesAllowGetSecretValue);
        internal const string RolesAllowReadCertificate = nameof(RolesAllowReadCertificate);
        internal const string RolesAllowSignWithKey = nameof(RolesAllowSignWithKey);
        internal const string RolesDenyGetSecretValue = nameof(RolesDenyGetSecretValue);
        internal const string RolesDenyReadCertificate = nameof(RolesDenyReadCertificate);
        internal const string RolesDenySignWithKey = nameof(RolesDenySignWithKey);
    }

    internal static void ExecuteInternal(IServiceProvider serviceProvider)
    {
        ArmClient armClient = AzureResourceContextProvider.GetOrCreateArmClient(
            serviceProvider
            );
        GenericResource keyVaultContentResource = armClient.GetGenericResource(
            GetKeyVaultContentResourceIdentifier(serviceProvider)
            );
        AuthorizationRoleDefinitionCollection roleDefinitions =
            keyVaultContentResource.GetAuthorizationRoleDefinitions();

    }

    private static ResourceIdentifier GetKeyVaultContentResourceIdentifier(
        IServiceProvider serviceProvider
        )
    {
        ResolveKeyVaultReferencePlugin.ExecuteInternal(serviceProvider);
        var context = serviceProvider.Get<IPluginExecutionContext>();
        var keyVaultReference = (Entity)context.OutputParameters[
            ResolveKeyVaultReferencePlugin.OutputParameterNames.KeyVaultReference
            ];
        keyVaultReference.TryGetAttributeValue(
            KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyVaultResourceIdentifier,
            out string keyVaultResourceIdString);
        return new(keyVaultResourceIdString);
    }

    private static async Task EvaluateRoleDefinitionsAsync(
        IServiceProvider serviceProvider,
        AuthorizationRoleDefinitionCollection roleDefinitions
        )
    {
        AsyncPageable<AuthorizationRoleDefinitionResource> builtInRoleDefinitions =
            roleDefinitions.GetAllAsync(filter: "type eq 'BuiltInRole'");
        await EvaluateRoleDefinitionsAsync(serviceProvider, builtInRoleDefinitions)
            .ConfigureAwait(continueOnCapturedContext: false);
        AsyncPageable<AuthorizationRoleDefinitionResource> customRoleDefinitions =
            roleDefinitions.GetAllAsync(filter: "type eq 'CustomRole'");
        await EvaluateRoleDefinitionsAsync(serviceProvider, customRoleDefinitions)
            .ConfigureAwait(continueOnCapturedContext: false);
    }

    private static async Task EvaluateRoleDefinitionsAsync(
        IServiceProvider serviceProvider,
        AsyncPageable<AuthorizationRoleDefinitionResource> roleDefinitions
        )
    {
        await foreach (AuthorizationRoleDefinitionResource roleDefinition in
            roleDefinitions.ConfigureAwait(continueOnCapturedContext: false))
        {
            EvaluateRoleDefinition(serviceProvider, roleDefinition);
        }
    }

    private static void EvaluateRoleDefinition(
        IServiceProvider serviceProvider,
        AuthorizationRoleDefinitionResource roleDefinition
        )
    {
        const string getSecretAction = "Microsoft.KeyVault/vaults/secrets/getSecret/action";
        const string readCertificateAction = "Microsoft.KeyVault/vaults/certificates/read";
        const string signWithKeyAction = "Microsoft.KeyVault/vaults/keys/sign/action";

        var context = serviceProvider.Get<IPluginExecutionContext>();

        bool anyDenied = false;
        foreach (RoleDefinitionPermission rolePermission in roleDefinition.Data.Permissions)
        {
            foreach (string deniedDataAction in rolePermission.NotDataActions)
            {
                if (IsDataActionMatch(deniedDataAction, getSecretAction))
                {
                    anyDenied = true;
                    EntityCollection entities = GetOrCreateEntityCollection(
                        context.OutputParameters,
                        OutputParameterNames.RolesDenyGetSecretValue
                        );
                    entities.Entities.Add(ToOutputEntity(roleDefinition));
                }
                if (IsDataActionMatch(deniedDataAction, readCertificateAction))
                {
                    anyDenied = true;
                    EntityCollection entities = GetOrCreateEntityCollection(
                        context.OutputParameters,
                        OutputParameterNames.RolesDenyReadCertificate
                        );
                    entities.Entities.Add(ToOutputEntity(roleDefinition));
                }
                if (IsDataActionMatch(deniedDataAction, signWithKeyAction))
                {
                    anyDenied = true;
                    EntityCollection entities = GetOrCreateEntityCollection(
                        context.OutputParameters,
                        OutputParameterNames.RolesDenySignWithKey
                        );
                    entities.Entities.Add(ToOutputEntity(roleDefinition));
                }
            }
            if (anyDenied) continue;
            foreach (string deniedDataAction in rolePermission.DataActions)
            {
                if (IsDataActionMatch(deniedDataAction, getSecretAction))
                {
                    anyDenied = true;
                    EntityCollection entities = GetOrCreateEntityCollection(
                        context.OutputParameters,
                        OutputParameterNames.RolesAllowGetSecretValue
                        );
                    entities.Entities.Add(ToOutputEntity(roleDefinition));
                }
                if (IsDataActionMatch(deniedDataAction, readCertificateAction))
                {
                    anyDenied = true;
                    EntityCollection entities = GetOrCreateEntityCollection(
                        context.OutputParameters,
                        OutputParameterNames.RolesAllowReadCertificate
                        );
                    entities.Entities.Add(ToOutputEntity(roleDefinition));
                }
                if (IsDataActionMatch(deniedDataAction, signWithKeyAction))
                {
                    anyDenied = true;
                    EntityCollection entities = GetOrCreateEntityCollection(
                        context.OutputParameters,
                        OutputParameterNames.RolesAllowSignWithKey
                        );
                    entities.Entities.Add(ToOutputEntity(roleDefinition));
                }
            }
        }

        static bool IsDataActionMatch(string dataActionTemplate, string dataAction)
        {
            if (!DataActionWildcardRegex.IsMatch(dataActionTemplate))
            {
                return dataActionTemplate.Equals(dataAction, StringComparison.OrdinalIgnoreCase);
            }

            string[] dataActionPartials = DataActionWildcardRegex.Split(dataActionTemplate);
            string dataActionRegexPattern = $"^{string.Join("[^\\/].*", dataActionPartials.Select(Regex.Escape))}$";
            return Regex.IsMatch(dataAction, dataActionRegexPattern);
        }
    }

    private static EntityCollection GetOrCreateEntityCollection(
        ParameterCollection outputs,
        string name
        )
    {
        if (outputs.TryGetValue(name, out EntityCollection entityCollection) &&
            entityCollection is not null)
        {
            return entityCollection;
        }
        entityCollection = new();
        outputs[name] = entityCollection;
        return entityCollection;
    }

    private static Entity ToOutputEntity(AuthorizationRoleDefinitionResource roleDefinition)
    {
        Entity entity = new();
        entity[nameof(ResourceIdentifier)] = roleDefinition.Id.ToString();
        entity[nameof(roleDefinition.Data.RoleName)] = roleDefinition.Data.RoleName;
        entity[nameof(roleDefinition.Data.Description)] = roleDefinition.Data.Description;
        entity[nameof(roleDefinition.Data.RoleType)] = roleDefinition.Data.RoleType.ToString();
        return entity;
    }

    private static readonly Regex DataActionWildcardRegex =
        new("(?<=^|\\/)\\*(?=$|\\/)");
}