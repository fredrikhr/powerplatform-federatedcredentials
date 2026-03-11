using Microsoft.Crm.Sdk.Messages;
using Microsoft.Xrm.Sdk.Query;

using Azure.Core;
using Azure.ResourceManager;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public sealed class PluginContext
{
    internal const string PrivilegeNameImpersonation = "prvActOnBehalfOfAnotherUser";
    private static readonly string[] PrivilegeNamesImpersonation = [PrivilegeNameImpersonation];

    private readonly Lazy<IOrganizationService> _defaultDataverseClient;
    private readonly Lazy<IOrganizationService> _userDataverseClient;
    private readonly Lazy<SystemUser> _userApplicationEntity;
    private readonly Lazy<bool> _userHasImpersonationPrivilege;
    private readonly Lazy<ManagedIdentity?> _pluginManagedIdentityEntity;
    private readonly Lazy<SystemUser?> _pluginApplicationEntity;

    private readonly Lazy<ManagedIdentityAzureCredential> _azureTokenCredential;
    private readonly Lazy<ArmClient> _azureResourceManagerClient;

    private readonly Lazy<ManagedIdentity?> _requestedManagedIdentity;
    private readonly Lazy<KeyVaultReference?> _resolvedKeyVaultReferenceEntity;
    private readonly Lazy<ResourceIdentifier?> _resolvedKeyVaultReferenceResourceId;

    internal IServiceProvider ServiceProvider { get; }
    internal IPluginExecutionContext7 ExecutionContext { get; }
    internal ParameterCollection Inputs => ExecutionContext.InputParameters;
    internal ParameterCollection Outputs => ExecutionContext.OutputParameters;

    internal PluginContext(IServiceProvider serviceProvider)
    {
        ServiceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        ExecutionContext = serviceProvider.Get<IPluginExecutionContext7>();

        _defaultDataverseClient = new(
            () => ServiceProvider.Get<IOrganizationServiceFactory>()
                .CreateOrganizationService(null)
            );
        _userDataverseClient = new(
            () => ServiceProvider.GetOrganizationService(ExecutionContext.UserId)
            );
        _userApplicationEntity = new(() =>
        {
            IOrganizationService dataverseSvc = UserDataverseClient;
            var systemUserEntity = dataverseSvc.Retrieve(
                SystemUser.EntityLogicalName,
                ExecutionContext.UserId,
                SystemUser.ApplicationSystemUserColumnSet
                ).ToEntity<SystemUser>();
            return systemUserEntity;
        });
        _userHasImpersonationPrivilege = new(() =>
        {
            IOrganizationService dataverseService = UserDataverseClient;
            RetrieveAadUserSetOfPrivilegesByNamesRequest dataverseRequest = new()
            {
                DirectoryObjectId = ExecutionContext.UserAzureActiveDirectoryObjectId,
                PrivilegeNames = PrivilegeNamesImpersonation,
            };
            var dataverseResponse = (RetrieveAadUserSetOfPrivilegesByNamesResponse)
                dataverseService.Execute(dataverseRequest);
            return (dataverseResponse.RolePrivileges?.Length ?? 0) > 0;
        });
        _pluginManagedIdentityEntity = new(() =>
        {
            IOrganizationService dataverseService = DefaultDataverseClient;
            var sdkStepEntity = dataverseService.Retrieve(
                ExecutionContext.OwningExtension?.LogicalName!
                ?? SdkMessageProcessingStep.EntityLogicalName,
                ExecutionContext.OwningExtension?.Id ?? Guid.Empty,
                SdkMessageProcessingStep.ColumnSet
                ).ToEntity<SdkMessageProcessingStep>();
            if (!sdkStepEntity.TryGetAttributeValue(
                    SdkMessageProcessingStep.Fields.PluginTypeId,
                    out EntityReference? pluginTypeEntityRef
                    ) ||
                    pluginTypeEntityRef is null
                )
            { return null; }

            var pluginTypeEntity = dataverseService.Retrieve(
                PluginType.EntityLogicalName,
                pluginTypeEntityRef.Id,
                PluginType.ColumnSet
                ).ToEntity<PluginType>();
            if (pluginTypeEntity.PluginAssemblyId is not EntityReference pluginAssemblyEntityRef)
            { return null; }

            var pluginAssemblyEntity = dataverseService.Retrieve(
                PluginAssembly.EntityLogicalName,
                pluginAssemblyEntityRef.Id,
                PluginAssembly.ColumnSet
                ).ToEntity<PluginAssembly>();
            if (pluginAssemblyEntity.ManagedIdentityId is EntityReference managedIdentityEntityRef)
            {
                return dataverseService.Retrieve(
                    ManagedIdentity.EntityLogicalName,
                    managedIdentityEntityRef.Id,
                    ManagedIdentity.ColumnSet
                    ).ToEntity<ManagedIdentity>();
            }

            if (pluginAssemblyEntity.PackageId is not EntityReference pluginPackageEntityRef)
            { return null; }

            var pluginPackageEntity = dataverseService.Retrieve(
                PluginPackage.EntityLogicalName,
                pluginPackageEntityRef.Id,
                PluginPackage.ColumnSet
                ).ToEntity<PluginPackage>();
#pragma warning disable IDE0046 // Convert to conditional expression
            if ((managedIdentityEntityRef = pluginPackageEntity.managedidentityid) is not null)
            {
                return dataverseService.Retrieve(
                    ManagedIdentity.EntityLogicalName,
                    managedIdentityEntityRef.Id,
                    ManagedIdentity.ColumnSet
                    ).ToEntity<ManagedIdentity>();
            }
#pragma warning restore IDE0046 // Convert to conditional expression

            return null;
        });
        _pluginApplicationEntity = new(() =>
        {
            if (PluginManagedIdentity is not ManagedIdentity pluginManagedIdentity)
            { return null; }
            if (pluginManagedIdentity is not { ApplicationId: Guid pluginAppId })
            { return null; }
            IOrganizationService dataverseClient = DefaultDataverseClient;
            QueryExpression appUsersQuery = new(SystemUser.EntityLogicalName)
            {
                TopCount = 1,
                ColumnSet = SystemUser.ApplicationSystemUserColumnSet,
                Criteria =
                {
                    Conditions =
                    {
                        new(SystemUser.Fields.ApplicationId, ConditionOperator.Equal, pluginAppId),
                    },
                },
            };
            EntityCollection matchingAppUserEntities = dataverseClient.RetrieveMultiple(appUsersQuery);
            return matchingAppUserEntities.Entities is [Entity matchingAppUserEntity, ..]
                ? matchingAppUserEntity.ToEntity<SystemUser>()
                : null;
        });

        _azureTokenCredential = new(() => new(ServiceProvider));
        _azureResourceManagerClient = new(() =>
        {
            TokenCredential tokenCredential = AzureTokenCredential;
            ArmClientOptions armClientOptions = new();
            ArmClient armClient = new(tokenCredential, default, armClientOptions);
            return armClient;
        });

        _requestedManagedIdentity = new(() =>
        {
            ParameterCollection outputs = [];
            RetrieveRequestedManagedIdentityPlugin
                .ExecuteInternal(this, outputs);
            _ = outputs.TryGetValue(
                RetrieveRequestedManagedIdentityPlugin.OutputParameterNames.RequestedManagedIdentity,
                out ManagedIdentity? managedIdentity
                );
            return managedIdentity;
        });

        _resolvedKeyVaultReferenceEntity = new(() =>
        {
            ParameterCollection outputs = [];
            ResolveKeyVaultReferencePlugin.ExecuteInternal(this, outputs);
            _ = outputs.TryGetValue(
                ResolveKeyVaultReferencePlugin.OutputParameterNames.KeyVaultReference,
                out KeyVaultReference? keyVaultReferenceEntity
                );
            return keyVaultReferenceEntity;
        });
        _resolvedKeyVaultReferenceResourceId = new(() =>
        {
            if (!_resolvedKeyVaultReferenceEntity.IsValueCreated &&
                Inputs.TryGetValue(
                ResolveKeyVaultReferencePlugin.InputParameterNames.KeyVaultResourceIdentifier,
                out string? keyVaultResourceIdString) &&
                ResourceIdentifier.TryParse(
                keyVaultResourceIdString,
                out ResourceIdentifier? keyVaultResourceId
                ))
            {
                return keyVaultResourceId;
            }
            else
            {
                return ResolvedKeyVaultReferenceEntity
                is KeyVaultReference keyVaultReferenceEntity2 &&
                keyVaultReferenceEntity2.TryGetAttributeValue(
                    KeyVaultReference.Fields.KeyVaultResourceIdentifier,
                    out keyVaultResourceIdString
                    ) &&
                ResourceIdentifier.TryParse(
                    keyVaultResourceIdString,
                    out keyVaultResourceId
                    )
                ? keyVaultResourceId
                : null;
            }
        });
    }

    internal IOrganizationService DefaultDataverseClient =>
        _defaultDataverseClient.Value;
    internal IOrganizationService UserDataverseClient =>
        _userDataverseClient.Value;
    internal SystemUser UserApplicationEntity => _userApplicationEntity.Value;
    internal Guid? UserApplicationId => ExecutionContext.IsApplicationUser
        ? UserApplicationEntity.ApplicationId
        : null;
    internal bool UserHasImpersonationPrivilege =>
        _userHasImpersonationPrivilege.Value;
    internal ManagedIdentity? PluginManagedIdentity =>
        _pluginManagedIdentityEntity.Value;
    internal SystemUser? PluginApplicationEntity =>
        _pluginApplicationEntity.Value;

    internal ManagedIdentityAzureCredential AzureTokenCredential =>
        _azureTokenCredential.Value;
    internal ArmClient AzureResourceManagerClient =>
        _azureResourceManagerClient.Value;

    internal ManagedIdentity? RequestedManagedIdentity =>
        _requestedManagedIdentity.Value;

    internal KeyVaultReference? ResolvedKeyVaultReferenceEntity =>
        _resolvedKeyVaultReferenceEntity.Value;
    internal ResourceIdentifier? ResolvedKeyVaultReferenceResourceId =>
        _resolvedKeyVaultReferenceResourceId.Value;
}