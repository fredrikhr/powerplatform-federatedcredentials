using Microsoft.Crm.Sdk.Messages;

using Azure.Identity;

using FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins.EntityInfo;

namespace FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins;

public abstract class ServicePrincipalTokenAcquisitionPlugin
    : AccessTokenAcquisitionPluginBase
{
    internal static class InputParameterName
    {
        internal const string TenantId = nameof(TenantId);
        internal const string ApplicationId = nameof(ApplicationId);
        internal const string KeyVaultUri = nameof(KeyVaultUri);
        internal const string KeyVaultObjectName = nameof(KeyVaultObjectName);
        internal const string KeyVaultObjectType = nameof(KeyVaultObjectType);
        internal const string ResourceId = nameof(ResourceId);
    }

    private const string PrivilegeNameImpersonation = "prvActOnBehalfOfAnotherUser";
    private static readonly string[] PrivilegeNamesImpersonation = [PrivilegeNameImpersonation];

    protected abstract string AcquirePrimaryAccessToken(
        IServiceProvider serviceProvider,
        string resourceId
        );

    private static string AcquireSecondaryAccessToken(
        IServiceProvider serviceProvider,
        string keyVaultUri,
        KeyVaultReferenceKeyTypeOptionSet keyVaultObjectType,
        string keyVaultObjectName
        )
    {

    }

    protected override sealed string AcquireAccessToken(
        IServiceProvider serviceProvider
        )
    {
        Guid pluginTenantIdGuid = Guid.Empty;
        Guid pluginAppIdGuid = Guid.Empty;
        string? pluginTenantId = null;
        string? pluginAppId = null;
        if (GetExecutingPluginManagedIdentityRecord(serviceProvider) is
            Entity pluginManagedIdentityRecord)
        {
            if (
                pluginManagedIdentityRecord.TryGetAttributeValue(ManagedIdentityEntityInfo.AttributeLogicalName.TenantId, out pluginTenantIdGuid) &&
                pluginTenantIdGuid != Guid.Empty
                )
            { pluginTenantId = pluginTenantIdGuid.ToString(); }
            if (
                pluginManagedIdentityRecord.TryGetAttributeValue(ManagedIdentityEntityInfo.AttributeLogicalName.ApplicationId, out pluginAppIdGuid) &&
                pluginAppIdGuid != Guid.Empty
                )
            { pluginAppId = pluginAppIdGuid.ToString(); }
        }

        UnpackRequestedManagedIdentity(
            serviceProvider,
            out string tenantId,
            out string appId,
            out string? keyVaultUri,
            out KeyVaultReferenceKeyTypeOptionSet keyVaultObjectType,
            out string? keyVaultObjectName
        );
        Guid tenantIdGuid = Guid.Parse(tenantId);
        Guid appIdGuid = Guid.Parse(appId);

        var context = serviceProvider.Get<IPluginExecutionContext7>();
        string resourceId = context.InputParameterOrDefault<string?>(
            InputParameterName.ResourceId
            ) ?? throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing, empty or null-valued required input parameter: {InputParameterName.ResourceId}"
            );

        Guid userAppIdGuid = Guid.Empty;
        if (context.IsApplicationUser)
        {
            IOrganizationService dataverseService = serviceProvider
                .Get<IOrganizationServiceFactory>()
                .CreateOrganizationService(null);
            Entity systemUserEntity = dataverseService.Retrieve(
                ApplicationSystemUserEntityInfo.EntityLogicalName,
                context.UserId,
                ApplicationSystemUserEntityInfo.ColumnSet
                );
            systemUserEntity.TryGetAttributeValue(
                ApplicationSystemUserEntityInfo.AttributeLogicalName.ApplicationId,
                out userAppIdGuid
                );
        }

        if (!VerifyUserAllowedToAcquirePrimaryAccessToken(serviceProvider, tenantIdGuid, appIdGuid, userAppIdGuid))
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.Forbidden,
                message: $"User with Entra Object ID '{context.UserAzureActiveDirectoryObjectId}' is not authorized to acquire an access token with the requested parameters. Missing privilege '{PrivilegeNameImpersonation}' for BU '{context.BusinessUnitId}'"
                );
        }

        if (
            pluginTenantIdGuid != Guid.Empty && pluginTenantIdGuid == tenantIdGuid &&
            pluginAppIdGuid != Guid.Empty && pluginAppIdGuid == appIdGuid
            )
        {
            return AcquirePrimaryAccessToken(serviceProvider, resourceId);
        }

        if (string.IsNullOrEmpty(keyVaultUri))
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"No KeyVault URI specified."
                );
        }
        if (string.IsNullOrEmpty(keyVaultObjectName))
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"No KeyVault secret or certificate name specified."
                );
        }

        throw new NotImplementedException();
    }

    protected static Entity? GetExecutingPluginManagedIdentityRecord(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();
        var dataverseService = serviceProvider.Get<IOrganizationServiceFactory>()
            .CreateOrganizationService(null);
        Entity sdkStepEntity = dataverseService.Retrieve(
            context.OwningExtension?.LogicalName!
            ?? SdkMessageProcessingStepEntityInfo.EntityLogicalName,
            context.OwningExtension?.Id ?? Guid.Empty,
            SdkMessageProcessingStepEntityInfo.ColumnSet
            );
        if (
            !sdkStepEntity.TryGetAttributeValue(
                SdkMessageProcessingStepEntityInfo.AttributeLogicalName.PluginTypeId,
                out EntityReference? pluginTypeEntityRef
                ) ||
                pluginTypeEntityRef is null
            )
        { return null; }

        Entity pluginTypeEntity = dataverseService.Retrieve(
            pluginTypeEntityRef.LogicalName,
            pluginTypeEntityRef.Id,
            PluginTypeEntityInfo.ColumnSet
            );
        if (
            !pluginTypeEntity.TryGetAttributeValue(
                PluginTypeEntityInfo.AttributeLogicalName.PluginAssemblyId,
                out EntityReference? pluginAssemblyEntityRef
                ) ||
            pluginAssemblyEntityRef is null
            )
        { return null; }

        Entity pluginAssemblyEntity = dataverseService.Retrieve(
            pluginAssemblyEntityRef.LogicalName,
            pluginAssemblyEntityRef.Id,
            PluginAssemblyEntityInfo.ColumnSet
            );
        if (
            pluginAssemblyEntity.TryGetAttributeValue(
                PluginAssemblyEntityInfo.AttributeLogicalName.ManagedIdentityId,
                out EntityReference? managedIdentityEntityRef
                ) &&
            managedIdentityEntityRef is not null
            )
        {
            return dataverseService.Retrieve(
                managedIdentityEntityRef.LogicalName,
                managedIdentityEntityRef.Id,
                ManagedIdentityEntityInfo.ColumnSet
                );
        }

        if (
            !pluginAssemblyEntity.TryGetAttributeValue(
                PluginAssemblyEntityInfo.AttributeLogicalName.PackageId,
                out EntityReference? pluginPackageEntityRef
                ) ||
            pluginPackageEntityRef is null
            )
        { return null; }

        Entity pluginPackageEntity = dataverseService.Retrieve(
            pluginPackageEntityRef.LogicalName,
            pluginPackageEntityRef.Id,
            PluginAssemblyEntityInfo.ColumnSet
            );
#pragma warning disable IDE0046 // Convert to conditional expression
        if (
            pluginPackageEntity.TryGetAttributeValue(
                PluginPackageEntityInfo.AttributeLogicalName.ManagedIdentityId,
                out managedIdentityEntityRef
                ) &&
                managedIdentityEntityRef is not null
            )
        {
            return dataverseService.Retrieve(
                managedIdentityEntityRef.LogicalName,
                managedIdentityEntityRef.Id,
                ManagedIdentityEntityInfo.ColumnSet
                );
        }
#pragma warning restore IDE0046 // Convert to conditional expression

        return null;
    }

    private static void UnpackRequestedManagedIdentityFromEntity(
        IOrganizationService dataverseService,
        string managedIdentityEntityLogicalName,
        Guid managedIdentityEntityId,
        out string? tenantId,
        out string applicationId,
        out string? keyvaultUri,
        out KeyVaultReferenceKeyTypeOptionSet keyvaultObjectType,
        out string? keyvaultObjectName
        )
    {
        tenantId = null;
        applicationId = null!;
        keyvaultUri = null!;
        keyvaultObjectType = KeyVaultReferenceKeyTypeOptionSet.Unknown;
        keyvaultObjectName = null!;

        Entity managedIdentityEntity = dataverseService.Retrieve(
            managedIdentityEntityLogicalName,
            managedIdentityEntityId,
            ManagedIdentityEntityInfo.ColumnSet
            );
        if (
            !managedIdentityEntity.TryGetAttributeValue(
                ManagedIdentityEntityInfo.AttributeLogicalName.Statecode,
                out OptionSetValue? managedIdentityState
                ) ||
            managedIdentityState is not { Value: ManagedIdentityEntityInfo.StatecodeActiveOptionValue }
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: "Requested Managed Identity record is not active."
                );
        }

        if (
            managedIdentityEntity.TryGetAttributeValue(
                ManagedIdentityEntityInfo.AttributeLogicalName.ApplicationId,
                out Guid applicationGuidValue
                ) &&
            applicationGuidValue != Guid.Empty
            )
        { applicationId = applicationGuidValue.ToString(); }

        if (
            managedIdentityEntity.TryGetAttributeValue(
                ManagedIdentityEntityInfo.AttributeLogicalName.TenantId,
                out Guid tenantGuidValue
                )
            )
        { tenantId = tenantGuidValue.ToString(); }

        if (
            !managedIdentityEntity.TryGetAttributeValue(
                ManagedIdentityEntityInfo.AttributeLogicalName.CredentialSource,
                out OptionSetValue? managedIdentityCredentialSource
                ) ||
            managedIdentityCredentialSource is not { Value: ManagedIdentityEntityInfo.CredentialSourceKeyVaultOptionValue }
            )
        {
            return;
        }

        if (
            !managedIdentityEntity.TryGetAttributeValue(
                ManagedIdentityEntityInfo.AttributeLogicalName.KeyVaultReferenceId,
                out EntityReference? keyvaultInfoEntityRef
                ) ||
            keyvaultInfoEntityRef is null
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: "Requested Managed Identity record has no related KeyVault Reference."
                );
        }

        Entity keyvaultInfoEntity = dataverseService.Retrieve(
            keyvaultInfoEntityRef.LogicalName,
            keyvaultInfoEntityRef.Id,
            KeyVaultReferenceEntityInfo.ColumnSet
            );

        if (!keyvaultInfoEntity.TryGetAttributeValue(
                KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyVaultUri,
                out keyvaultUri
                ) ||
                string.IsNullOrEmpty(keyvaultUri)
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: "KeyVault Reference associated with requested Managed Identity does not specify a KeyVault URI."
                );
        }
        if (!keyvaultInfoEntity.TryGetAttributeValue(
                KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyName,
                out keyvaultObjectName
                ) ||
                string.IsNullOrEmpty(keyvaultObjectName)
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: "KeyVault Reference associated with requested Managed Identity does not specify the name of the referenced secret or certificate."
                );
        }
        if (!keyvaultInfoEntity.TryGetAttributeValue(
                KeyVaultReferenceEntityInfo.AttributeLogicalName.KeyType,
                out OptionSetValue? keyvaultObjectTypeOptionSetValue
                ) ||
                keyvaultObjectTypeOptionSetValue is not { Value: int keyvaultObjectTypeCode }
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: "KeyVault Reference associated with requested Managed Identity does not specify the type of the referenced secret or certificate."
                );
        }
        keyvaultObjectType = (KeyVaultReferenceKeyTypeOptionSet)keyvaultObjectTypeCode;
    }

    private static void UnpackRequestedManagedIdentityFromParameters(
        ParameterCollection inputParameters,
        out string? tenantId,
        out string applicationId,
        out string? keyvaultUri,
        out KeyVaultReferenceKeyTypeOptionSet keyvaultObjectType,
        out string? keyvaultObjectName
        )
    {
        tenantId = inputParameters
            .TryGetValue(InputParameterName.TenantId, out var tenantInputParam)
            ? tenantInputParam switch
            {
                Guid tenantIdGuid when tenantIdGuid != Guid.Empty => tenantIdGuid.ToString(),
                string tenantIdString => tenantIdString,
                _ => null,
            }
            : null;
        applicationId = inputParameters
            .TryGetValue(InputParameterName.ApplicationId, out var appIdInputParam)
            ? appIdInputParam switch
            {
                Guid appIdGuid when appIdGuid != Guid.Empty => appIdGuid.ToString(),
                string appIdString => appIdString,
                _ => null!,
            }
            : null!;
        inputParameters.TryGetValue(
            InputParameterName.KeyVaultUri,
            out keyvaultUri
            );
        keyvaultObjectType = inputParameters
            .TryGetValue(InputParameterName.KeyVaultObjectType, out var keyvaultObjectTypeInputParam)
            ? keyvaultObjectTypeInputParam switch
            {
                string keyvaultObjectTypeString => (KeyVaultReferenceKeyTypeOptionSet)Enum.Parse(
                    typeof(KeyVaultReferenceKeyTypeOptionSet),
                    keyvaultObjectTypeString,
                    ignoreCase: true
                    ),
                int keyvaultObjectTypeCode => (KeyVaultReferenceKeyTypeOptionSet)
                    keyvaultObjectTypeCode,
                OptionSetValue { Value: int keyvaultObjectTypeCode } =>
                    (KeyVaultReferenceKeyTypeOptionSet)keyvaultObjectTypeCode,
                _ => KeyVaultReferenceKeyTypeOptionSet.Unknown,
            }
            : KeyVaultReferenceKeyTypeOptionSet.Unknown;
        inputParameters.TryGetValue(
            InputParameterName.KeyVaultObjectName,
            out keyvaultObjectName
            );
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1054: URI-like parameters should not be strings",
        Justification = nameof(IPluginExecutionContext.InputParameters)
        )]
    private static void UnpackRequestedManagedIdentity(
        IServiceProvider serviceProvider,
        out string tenantId,
        out string applicationId,
        out string? keyvaultUri,
        out KeyVaultReferenceKeyTypeOptionSet keyvaultObjectType,
        out string? keyvaultObjectName
        )
    {
        var context = serviceProvider.Get<IPluginExecutionContext6>();

        string? tmpTenantId;
        if (
            ManagedIdentityEntityInfo.EntityLogicalName.Equals(
                context.PrimaryEntityName,
                StringComparison.OrdinalIgnoreCase
                ) &&
            context.PrimaryEntityId != Guid.Empty
            )
        {
            IOrganizationService dataverseService = serviceProvider
                .GetOrganizationService(context.UserId);
            UnpackRequestedManagedIdentityFromEntity(
                dataverseService,
                context.PrimaryEntityName,
                context.PrimaryEntityId,
                out tmpTenantId,
                out applicationId,
                out keyvaultUri,
                out keyvaultObjectType,
                out keyvaultObjectName
                );
        }
        else
        {
            UnpackRequestedManagedIdentityFromParameters(
                context.InputParameters,
                out tmpTenantId,
                out applicationId,
                out keyvaultUri,
                out keyvaultObjectType,
                out keyvaultObjectName
                );
        }

        if (string.IsNullOrEmpty(tmpTenantId))
        {
            tmpTenantId = context.TenantId.ToString();
        }
        tenantId = tmpTenantId!;

        if (string.IsNullOrEmpty(applicationId))
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: "No application ID specified."
                );
        }
    }

    private static bool VerifyUserAllowedToAcquirePrimaryAccessToken(
        IServiceProvider serviceProvider,
        Guid requestedTenantId,
        Guid requestedApplicationId,
        Guid userApplicationId
        )
    {
        var context = serviceProvider.Get<IPluginExecutionContext6>();

        if (
            requestedApplicationId != Guid.Empty &&
            requestedApplicationId == userApplicationId &&
            (
                requestedTenantId == Guid.Empty ||
                requestedTenantId == context.TenantId
            ))
        { return true; }

        IOrganizationService dataverseService = serviceProvider
            .Get<IOrganizationServiceFactory>()
            .CreateOrganizationService(null);
        RetrieveAadUserSetOfPrivilegesByNamesRequest dataverseRequest = new()
        {
            DirectoryObjectId = context.UserAzureActiveDirectoryObjectId,
            PrivilegeNames = PrivilegeNamesImpersonation,
        };
        var dataverseResponse = (RetrieveAadUserSetOfPrivilegesByNamesResponse)
            dataverseService.Execute(dataverseRequest);
        foreach (RolePrivilege prv in dataverseResponse.RolePrivileges)
        {
            if (prv.BusinessUnitId == context.BusinessUnitId)
            {
                return true;
            }
        }

        return false;
    }
}