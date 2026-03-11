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

    protected override void ExecuteCore(PluginContext context)
    {
        _ = context ?? throw new ArgumentNullException(nameof(context));
        ExecuteInternal(context, context.Outputs);
    }

    internal static void ExecuteInternal(
        PluginContext context,
        ParameterCollection? outputs = null
        )
    {
        outputs ??= context.Outputs;
        ArmClient armClient = context.AzureResourceManagerClient;
        ResourceIdentifier keyVaultContentResourceId =
            GetKeyVaultDataResourceIdentifier(context);
        GenericResource keyVaultContentResource = armClient
            .GetGenericResource(keyVaultContentResourceId);
        AuthorizationRoleDefinitionCollection roleDefinitions =
            keyVaultContentResource.GetAuthorizationRoleDefinitions();
        EvaluateRoleDefinitionsAsync(roleDefinitions, outputs)
            .GetAwaiter().GetResult();
        EvaluateAccessPermissions(
            context,
            context.ResolvedKeyVaultReferenceEntity,
            keyVaultContentResource,
            outputs
            ).GetAwaiter().GetResult();
    }

    private static ResourceIdentifier GetKeyVaultDataResourceIdentifier(
        PluginContext context
        )
    {
        ResourceIdentifier? keyVaultContentResourceId;
        for (keyVaultContentResourceId = context.ResolvedKeyVaultReferenceResourceId;
                keyVaultContentResourceId is not null &&
                keyVaultContentResourceId.ResourceType != KeyVaultSecretResourceType &&
                keyVaultContentResourceId.ResourceType != KeyVaultCertificateResourceType;
                keyVaultContentResourceId = keyVaultContentResourceId.Parent
                ) ;
        return keyVaultContentResourceId is not null
            ? keyVaultContentResourceId
            : throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Provided KeyVault resource ID '{keyVaultContentResourceId}' is not a valid Resource ID for a KeyVault secret or certificate."
                );
    }

    private static async Task EvaluateRoleDefinitionsAsync(
        AuthorizationRoleDefinitionCollection roleDefinitions,
        ParameterCollection outputs
        )
    {
        AsyncPageable<AuthorizationRoleDefinitionResource> builtInRoleDefinitions =
            roleDefinitions.GetAllAsync(filter: "type eq 'BuiltInRole'");
        await EvaluateRoleDefinitionsAsync(builtInRoleDefinitions, outputs)
            .ConfigureAwait(continueOnCapturedContext: false);
        AsyncPageable<AuthorizationRoleDefinitionResource> customRoleDefinitions =
            roleDefinitions.GetAllAsync(filter: "type eq 'CustomRole'");
        await EvaluateRoleDefinitionsAsync(customRoleDefinitions, outputs)
            .ConfigureAwait(continueOnCapturedContext: false);
    }

    private static async Task EvaluateRoleDefinitionsAsync(
        AsyncPageable<AuthorizationRoleDefinitionResource> roleDefinitions,
        ParameterCollection outputs
        )
    {
        await foreach (AuthorizationRoleDefinitionResource roleDefinition in
            roleDefinitions.ConfigureAwait(continueOnCapturedContext: false))
        {
            EvaluateRoleDefinition(roleDefinition, outputs);
        }
    }

    private static readonly Regex DataActionWildcardRegex =
        new("(?<=^|\\/)\\*(?=$|\\/)");

    private const string GetSecretAction = "Microsoft.KeyVault/vaults/secrets/getSecret/action";
    private const string ReadCertificateAction = "Microsoft.KeyVault/vaults/certificates/read";
    private const string SignWithKeyAction = "Microsoft.KeyVault/vaults/keys/sign/action";

    private static void EvaluateRoleDefinition(
        AuthorizationRoleDefinitionResource roleDefinition,
        ParameterCollection outputs
        )
    {
        bool anyDenied = false;
        foreach (RoleDefinitionPermission rolePermission in roleDefinition.Data.Permissions)
        {
            foreach (string deniedDataAction in rolePermission.NotDataActions)
            {
                if (IsDataActionMatch(deniedDataAction, GetSecretAction))
                {
                    anyDenied = true;
                    EntityCollection entities = GetOrCreateEntityCollection(
                        outputs,
                        OutputParameterNames.RolesDenyGetSecretValue
                        );
                    entities.Entities.Add(ToOutputEntity(roleDefinition));
                }
                if (IsDataActionMatch(deniedDataAction, ReadCertificateAction))
                {
                    anyDenied = true;
                    EntityCollection entities = GetOrCreateEntityCollection(
                        outputs,
                        OutputParameterNames.RolesDenyReadCertificate
                        );
                    entities.Entities.Add(ToOutputEntity(roleDefinition));
                }
                if (IsDataActionMatch(deniedDataAction, SignWithKeyAction))
                {
                    anyDenied = true;
                    EntityCollection entities = GetOrCreateEntityCollection(
                        outputs,
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
                        outputs,
                        OutputParameterNames.RolesAllowGetSecretValue
                        );
                    entities.Entities.Add(ToOutputEntity(roleDefinition));
                }
                if (IsDataActionMatch(deniedDataAction, ReadCertificateAction))
                {
                    anyDenied = true;
                    EntityCollection entities = GetOrCreateEntityCollection(
                        outputs,
                        OutputParameterNames.RolesAllowReadCertificate
                        );
                    entities.Entities.Add(ToOutputEntity(roleDefinition));
                }
                if (IsDataActionMatch(deniedDataAction, SignWithKeyAction))
                {
                    anyDenied = true;
                    EntityCollection entities = GetOrCreateEntityCollection(
                        outputs,
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
        PluginContext context,
        KeyVaultReference? keyVaultReferenceEntity,
        GenericResource keyVaultResource,
        ParameterCollection? outputs = null
        )
    {
        outputs ??= context.Outputs;
        KeyVaultDataAccessPermisions possiblePermissions =
            KeyVaultDataAccessPermisions.GetSecret |
            KeyVaultDataAccessPermisions.ReadCertificateProperties |
            KeyVaultDataAccessPermisions.SignWithKey;
        KeyVaultDataAccessPermisions effectivePermissions =
            KeyVaultDataAccessPermisions.None;
        ArmClient armClient = context.AzureResourceManagerClient;
        keytype keyVaultDataType = keyVaultReferenceEntity?.KeyType
            ?? (keytype)(-1);
        string assignmentFilter = $"atScope() and assignedTo('{context.ExecutionContext.UserAzureActiveDirectoryObjectId}')";
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
                            outputs,
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
                            outputs,
                            OutputParameterNames.RolesDenyReadCertificate
                            );
                        if (ContainsRoleDefinition(roleDefinitions, roleAssignment.Data.RoleDefinitionId))
                        {
                            possiblePermissions &= ~KeyVaultDataAccessPermisions.ReadCertificateProperties;
                        }
                        roleDefinitions = GetOrCreateEntityCollection(
                            outputs,
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
                                outputs,
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
                                outputs,
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
                                outputs,
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

        outputs[OutputParameterNames.UserEffectivePermissions] =
            (int)effectivePermissions;
        outputs[OutputParameterNames.UserEffectivePermissionsDisplayName] =
            effectivePermissions.ToString();
        outputs[OutputParameterNames.UserHasSufficientPermissions] =
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