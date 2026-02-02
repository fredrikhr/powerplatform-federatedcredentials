using System.Text.RegularExpressions;

using Azure;
using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.Authorization;
using Azure.ResourceManager.Authorization.Models;
using Azure.ResourceManager.Resources;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class EvaluateKeyVaultDataAccessPermissionsPlugin : PluginBase, IPlugin
{
    private static readonly ResourceType KeyVaultSecretResourceType =
        "Microsoft.KeyVault/vaults/secrets";
    private static readonly ResourceType KeyVaultCertificateResourceType =
        "Microsoft.KeyVault/vaults/certificates";

    internal static class OutputParameterNames
    {
        internal const string RolesAllowGetSecretValue = nameof(RolesAllowGetSecretValue);
        internal const string RolesAllowReadCertificate = nameof(RolesAllowReadCertificate);
        internal const string RolesAllowSignWithKey = nameof(RolesAllowSignWithKey);
        internal const string RolesDenyGetSecretValue = nameof(RolesDenyGetSecretValue);
        internal const string RolesDenyReadCertificate = nameof(RolesDenyReadCertificate);
        internal const string RolesDenySignWithKey = nameof(RolesDenySignWithKey);
        internal const string UserHasSufficientPermissions = nameof(UserHasSufficientPermissions);
        internal const string UserEffectivePermissions = nameof(UserEffectivePermissions);
        internal const string UserEffectivePermissionsDisplayName = nameof(UserEffectivePermissionsDisplayName);
    }

    protected override void ExecuteCore(IServiceProvider serviceProvider)
    {
        ExecuteInternal(serviceProvider);
    }

    internal static void ExecuteInternal(IServiceProvider serviceProvider)
    {
        ArmClient armClient = AzureResourceContextProvider.GetOrCreateArmClient(
            serviceProvider
            );
        ResourceIdentifier keyVaultContentResourceId =
            GetKeyVaultDataResourceIdentifier(serviceProvider);
        GenericResource keyVaultContentResource = armClient
            .GetGenericResource(keyVaultContentResourceId);
        AuthorizationRoleDefinitionCollection roleDefinitions =
            keyVaultContentResource.GetAuthorizationRoleDefinitions();
        EvaluateRoleDefinitionsAsync(serviceProvider, roleDefinitions)
            .GetAwaiter().GetResult();
        EvaluateAccessPermissions(serviceProvider)
            .GetAwaiter().GetResult();
    }

    private static ResourceIdentifier GetKeyVaultDataResourceIdentifier(
        IServiceProvider serviceProvider, bool reentrantCall = false
        )
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();
        if (context.OutputParameters.TryGetValue(
            ResolveKeyVaultReferencePlugin.OutputParameterNames.KeyVaultResourceIdentifier,
            out string keyVaultResourceIdString
            ))
        {
            ResourceIdentifier? keyVaultContentResourceId;
            for (keyVaultContentResourceId = ResourceIdentifier.Parse(keyVaultResourceIdString);
                keyVaultContentResourceId is not null &&
                keyVaultContentResourceId.ResourceType != KeyVaultSecretResourceType &&
                keyVaultContentResourceId.ResourceType != KeyVaultCertificateResourceType;
                keyVaultContentResourceId = keyVaultContentResourceId.Parent
                ) ;
            if (keyVaultContentResourceId is null)
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Provided KeyVault resource ID '{keyVaultResourceIdString}' is not a valid Resource ID for a KeyVault secret or certificate."
                    );
            }
            return keyVaultContentResourceId;
        }
        else if (!reentrantCall)
        {
            ResolveKeyVaultReferencePlugin.ExecuteInternal(serviceProvider);
            return GetKeyVaultDataResourceIdentifier(serviceProvider, reentrantCall: true);
        }

        throw new InvalidPluginExecutionException(
            httpStatus: PluginHttpStatusCode.NotFound,
            message: "Unable to resolve Key Vault reference input parameters to an Azure Resource Manager Resource Identifier."
            );
    }

    private static keytype GetKeyVaultDataType(
        IServiceProvider serviceProvider, bool reentrantCall = false
        )
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();
        if (context.OutputParameters.TryGetValue(
            ResolveKeyVaultReferencePlugin.OutputParameterNames.KeyVaultReference,
            out Entity keyVaultReference
            ))
        {
            KeyVaultReference kvEntity = keyVaultReference switch
            {
                KeyVaultReference e => e,
                Entity e => e.ToEntity<KeyVaultReference>(),
                _ => throw new InvalidPluginExecutionException("KeyVaultReference entity not available."),
            };
            return kvEntity.KeyType ?? (keytype)(-1);
        }
        else if (!reentrantCall)
        {
            ResolveKeyVaultReferencePlugin.ExecuteInternal(serviceProvider);
            return GetKeyVaultDataType(serviceProvider, reentrantCall: true);
        }

        throw new InvalidPluginExecutionException(
            httpStatus: PluginHttpStatusCode.NotFound,
            message: "Unable to resolve Key Vault reference input parameters."
            );
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

    private static readonly Regex DataActionWildcardRegex =
        new("(?<=^|\\/)\\*(?=$|\\/)");

    private const string GetSecretAction = "Microsoft.KeyVault/vaults/secrets/getSecret/action";
    private const string ReadCertificateAction = "Microsoft.KeyVault/vaults/certificates/read";
    private const string SignWithKeyAction = "Microsoft.KeyVault/vaults/keys/sign/action";

    private static void EvaluateRoleDefinition(
        IServiceProvider serviceProvider,
        AuthorizationRoleDefinitionResource roleDefinition
        )
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();

        bool anyDenied = false;
        foreach (RoleDefinitionPermission rolePermission in roleDefinition.Data.Permissions)
        {
            foreach (string deniedDataAction in rolePermission.NotDataActions)
            {
                if (IsDataActionMatch(deniedDataAction, GetSecretAction))
                {
                    anyDenied = true;
                    EntityCollection entities = GetOrCreateEntityCollection(
                        context.OutputParameters,
                        OutputParameterNames.RolesDenyGetSecretValue
                        );
                    entities.Entities.Add(ToOutputEntity(roleDefinition));
                }
                if (IsDataActionMatch(deniedDataAction, ReadCertificateAction))
                {
                    anyDenied = true;
                    EntityCollection entities = GetOrCreateEntityCollection(
                        context.OutputParameters,
                        OutputParameterNames.RolesDenyReadCertificate
                        );
                    entities.Entities.Add(ToOutputEntity(roleDefinition));
                }
                if (IsDataActionMatch(deniedDataAction, SignWithKeyAction))
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
                if (IsDataActionMatch(deniedDataAction, GetSecretAction))
                {
                    anyDenied = true;
                    EntityCollection entities = GetOrCreateEntityCollection(
                        context.OutputParameters,
                        OutputParameterNames.RolesAllowGetSecretValue
                        );
                    entities.Entities.Add(ToOutputEntity(roleDefinition));
                }
                if (IsDataActionMatch(deniedDataAction, ReadCertificateAction))
                {
                    anyDenied = true;
                    EntityCollection entities = GetOrCreateEntityCollection(
                        context.OutputParameters,
                        OutputParameterNames.RolesAllowReadCertificate
                        );
                    entities.Entities.Add(ToOutputEntity(roleDefinition));
                }
                if (IsDataActionMatch(deniedDataAction, SignWithKeyAction))
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
    }

    private static bool IsDataActionMatch(string dataActionTemplate, string dataAction)
    {
        if (!DataActionWildcardRegex.IsMatch(dataActionTemplate))
        {
            return dataActionTemplate.Equals(dataAction, StringComparison.OrdinalIgnoreCase);
        }

        string[] dataActionPartials = DataActionWildcardRegex.Split(dataActionTemplate);
        string dataActionRegexPattern = $"^{string.Join("[^\\/].*", dataActionPartials.Select(Regex.Escape))}$";
        return Regex.IsMatch(dataAction, dataActionRegexPattern);
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

    private static async Task EvaluateAccessPermissions(
        IServiceProvider serviceProvider
        )
    {
        var context = serviceProvider.Get<IPluginExecutionContext2>();
        KeyVaultDataAccessPermisions possiblePermissions =
            KeyVaultDataAccessPermisions.GetSecret |
            KeyVaultDataAccessPermisions.ReadCertificateProperties |
            KeyVaultDataAccessPermisions.SignWithKey;
        KeyVaultDataAccessPermisions effectivePermissions =
            KeyVaultDataAccessPermisions.None;
        ArmClient armClient = AzureResourceContextProvider
            .GetOrCreateArmClient(serviceProvider);
        GenericResource keyVaultResource = armClient.GetGenericResource(
            GetKeyVaultDataResourceIdentifier(serviceProvider)
            );
        keytype keyVaultDataType = GetKeyVaultDataType(serviceProvider);
        string assignmentFilter = $"atScope() and assignedTo('{context.UserAzureActiveDirectoryObjectId}')";
        static bool IsGetSecretDataActionMatch(string dataActionTemplate) =>
                IsDataActionMatch(dataActionTemplate, GetSecretAction);
        static bool IsReadCertificateDataActionMatch(string dataActionTemplate) =>
            IsDataActionMatch(dataActionTemplate, ReadCertificateAction);
        static bool IsSignWithKeyDataActionMatch(string dataActionTemplate) =>
            IsDataActionMatch(dataActionTemplate, SignWithKeyAction);
        await foreach (DenyAssignmentResource denyAssigment in
            keyVaultResource.GetDenyAssignments().GetAllAsync(assignmentFilter)
            .ConfigureAwait(continueOnCapturedContext: false))
        {
            foreach (DenyAssignmentPermission denyPermission in denyAssigment.Data.Permissions)
            {
                if (denyPermission.DataActions.Any(IsGetSecretDataActionMatch) &&
                    !denyPermission.NotDataActions.Any(IsGetSecretDataActionMatch))
                {
                    possiblePermissions &= ~KeyVaultDataAccessPermisions.GetSecret;
                }

                if (denyPermission.DataActions.Any(IsReadCertificateDataActionMatch) &&
                    !denyPermission.NotDataActions.Any(IsReadCertificateDataActionMatch))
                {
                    possiblePermissions &= ~KeyVaultDataAccessPermisions.ReadCertificateProperties;
                }

                if (denyPermission.DataActions.Any(IsSignWithKeyDataActionMatch) &&
                    !denyPermission.NotDataActions.Any(IsSignWithKeyDataActionMatch))
                {
                    possiblePermissions &= ~KeyVaultDataAccessPermisions.SignWithKey;
                }
            }
        }

        bool isDenied = keyVaultDataType switch
        {
            keytype.Secret when
            possiblePermissions.HasFlag(KeyVaultDataAccessPermisions.GetSecret) => false,
            keytype.Certificate or
            keytype.CertificateWithX5c when
            possiblePermissions.HasFlag(KeyVaultDataAccessPermisions.ReadCertificateProperties | KeyVaultDataAccessPermisions.SignWithKey) => false,
            _ => true
        };

        if (!isDenied)
        {
            List<RoleAssignmentResource> roleAssignments = [];
            await foreach (RoleAssignmentResource roleAssignment in
                keyVaultResource.GetRoleAssignments().GetAllAsync(assignmentFilter)
                .ConfigureAwait(continueOnCapturedContext: false))
            {
                roleAssignments.Add(roleAssignment);
            }

            EntityCollection roleDefinitions;
            foreach (RoleAssignmentResource roleAssignment in roleAssignments)
            {
                switch (keyVaultDataType)
                {
                    case keytype.Secret:
                        roleDefinitions = GetOrCreateEntityCollection(
                            context.OutputParameters,
                            OutputParameterNames.RolesDenyGetSecretValue
                            );
                        if (ContainsRoleDefinition(roleDefinitions, roleAssignment.Data.RoleDefinitionId))
                        {
                            possiblePermissions &= ~KeyVaultDataAccessPermisions.GetSecret;
                        }
                        break;
                    case keytype.Certificate:
                    case keytype.CertificateWithX5c:
                        roleDefinitions = GetOrCreateEntityCollection(
                            context.OutputParameters,
                            OutputParameterNames.RolesDenyReadCertificate
                            );
                        if (ContainsRoleDefinition(roleDefinitions, roleAssignment.Data.RoleDefinitionId))
                        {
                            possiblePermissions &= ~KeyVaultDataAccessPermisions.ReadCertificateProperties;
                        }
                        roleDefinitions = GetOrCreateEntityCollection(
                            context.OutputParameters,
                            OutputParameterNames.RolesDenySignWithKey
                            );
                        if (ContainsRoleDefinition(roleDefinitions, roleAssignment.Data.RoleDefinitionId))
                        {
                            possiblePermissions &= ~KeyVaultDataAccessPermisions.SignWithKey;
                        }
                        break;
                }
            }

            foreach (RoleAssignmentResource roleAssignment in roleAssignments)
            {
                switch (keyVaultDataType)
                {
                    case keytype.Secret:
                        if (possiblePermissions.HasFlag(KeyVaultDataAccessPermisions.GetSecret))
                        {
                            roleDefinitions = GetOrCreateEntityCollection(
                                context.OutputParameters,
                                OutputParameterNames.RolesAllowGetSecretValue
                                );
                            if (ContainsRoleDefinition(roleDefinitions, roleAssignment.Data.RoleDefinitionId))
                            {
                                effectivePermissions |= KeyVaultDataAccessPermisions.GetSecret;
                            }
                        }
                        break;
                    case keytype.Certificate:
                    case keytype.CertificateWithX5c:
                        if (possiblePermissions.HasFlag(KeyVaultDataAccessPermisions.ReadCertificateProperties))
                        {
                            roleDefinitions = GetOrCreateEntityCollection(
                                context.OutputParameters,
                                OutputParameterNames.RolesAllowReadCertificate
                                );
                            if (ContainsRoleDefinition(roleDefinitions, roleAssignment.Data.RoleDefinitionId))
                            {
                                effectivePermissions |= KeyVaultDataAccessPermisions.ReadCertificateProperties;
                            }
                        }
                        if (possiblePermissions.HasFlag(KeyVaultDataAccessPermisions.SignWithKey))
                        {
                            roleDefinitions = GetOrCreateEntityCollection(
                                context.OutputParameters,
                                OutputParameterNames.RolesAllowSignWithKey
                                );
                            if (ContainsRoleDefinition(roleDefinitions, roleAssignment.Data.RoleDefinitionId))
                            {
                                effectivePermissions |= KeyVaultDataAccessPermisions.SignWithKey;
                            }
                        }
                        break;
                }
            }
        }

        bool hasSufficientPermissions = keyVaultDataType switch
        {
            keytype.Secret => effectivePermissions
                .HasFlag(KeyVaultDataAccessPermisions.GetSecret),
            keytype.Certificate or
            keytype.CertificateWithX5c => effectivePermissions
                .HasFlag(KeyVaultDataAccessPermisions.ReadCertificateProperties | KeyVaultDataAccessPermisions.SignWithKey),
            _ => false,
        };

        context.OutputParameters[OutputParameterNames.UserEffectivePermissions] =
            (int)effectivePermissions;
        context.OutputParameters[OutputParameterNames.UserEffectivePermissionsDisplayName] =
            effectivePermissions.ToString();
        context.OutputParameters[OutputParameterNames.UserHasSufficientPermissions] =
            hasSufficientPermissions;
    }

    private static bool ContainsRoleDefinition(
        EntityCollection roleDefinitions,
        ResourceIdentifier roleDefinitionId)
    {
        return roleDefinitions.Entities.Any(MatchesRoleDefinitionId);

        bool MatchesRoleDefinitionId(Entity entity)
        {
            return entity
                .TryGetAttributeValue(
                    nameof(ResourceIdentifier),
                    out string? entityResourceIdString
                    ) &&
                ResourceIdentifier.TryParse(
                    entityResourceIdString,
                    out ResourceIdentifier? entityResourceId
                    ) &&
                roleDefinitionId.Equals(entityResourceId);
        }
    }
}