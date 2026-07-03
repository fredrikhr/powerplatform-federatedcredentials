using Microsoft.Crm.Sdk.Messages;
using Microsoft.Xrm.Sdk.Query;

using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.Resources;
using Azure.ResourceManager.KeyVault;

using Microsoft.Identity.Client;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public sealed class PluginExecutionInformation
{
    private const StringComparison CmpOrdIgn = StringComparison.OrdinalIgnoreCase;

    internal static class InputParameterNames
    {
        public const string Application = nameof(Application);
        public const string ClientCredentialsSource = nameof(ClientCredentialsSource);
    }

    internal const string FallbackClientId = "00000007-0000-0000-c000-000000000000";
    internal const string PrivilegeNameImpersonation = "prvActOnBehalfOfAnotherUser";
    private static readonly string[] PrivilegeNamesImpersonation = [PrivilegeNameImpersonation];

    private readonly IServiceProvider _serviceProvider;
    private readonly ParameterCollection _inputs;
    private readonly ParameterCollection _outputs;
    private readonly Lazy<SystemUser?> _applicationSystemUser;
    private readonly Lazy<ManagedIdentity?> _pluginManagedIdentity;
    private readonly Lazy<SystemUser?> _pluginManagedIdentitySystemUser;
    private readonly Lazy<bool> _isUserPluginManagedIdentitySystemUser;
    private readonly Lazy<bool> _userHasImpersonationPrivilege;
    private readonly Lazy<bool> _isApplicationSelfRequest;
    private readonly Lazy<bool> _isPluginIdentityRequest;
    private readonly Lazy<ConfidentialClientApplicationOptions?> _msalClientOptions;
    private readonly Lazy<PluginClientCredentialsSource?> _clientCredentialsSource;
    private readonly Lazy<KeyVaultDataAccessPermisions> _clientCredentialsSourceAccessPermissions;
    private readonly Lazy<bool> _userHasSufficientClientCredentialsSourceAccessPermission;

    public PluginExecutionInformation(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
        var context = serviceProvider.Get<IPluginExecutionContext>();
        _inputs = context.InputParameters;
        _outputs = context.OutputParameters;

        _pluginManagedIdentity = new(RetrievePluginManagedIdentity);
        _pluginManagedIdentitySystemUser = new(RetrievePluginManagedIdentitySystemUser);
        _isUserPluginManagedIdentitySystemUser = new(EvaluateIsUserSameAsPlugin);
        _applicationSystemUser = new(RetrieveApplicationSystemUser);
        _userHasImpersonationPrivilege = new(EvaluateUserHasImpersonationPrivilege);
        _isApplicationSelfRequest = new(EvaluateIsApplicationSelfRequest);
        _isPluginIdentityRequest = new(EvaluateIsApplicationPluginIdentityRequest);
        _msalClientOptions = new(ConstructConfidentialClientApplicationOptions);

        _clientCredentialsSource = new(ResolveClientCredentialsSource);
        _clientCredentialsSourceAccessPermissions = new(EvaluateUserKeyVaultDataAccessPermissions);
        _userHasSufficientClientCredentialsSourceAccessPermission =
            new(EvaluateUserHasSufficientKeyVaultDataAccessPermissions);
    }

    public ITracingService TracingService
        => field ??= _serviceProvider.Get<ITracingService>();

    public IOrganizationServiceFactory DataverseClientFactory
        => field ??= _serviceProvider.Get<IOrganizationServiceFactory>();

    public IOrganizationService SystemDataverseClient
        => field ??= DataverseClientFactory.CreateOrganizationService(
            userId: null
            );

    public IOrganizationService DataverseClient
        => field ??= DataverseClientFactory.CreateOrganizationService(
            _serviceProvider.Get<IPluginExecutionContext>()?.UserId
            );

    public SystemUser? ApplicationSystemUser
        => _applicationSystemUser.Value;

    public ManagedIdentity? PluginManagedIdentity
        => _pluginManagedIdentity.Value;

    public SystemUser? PluginManagedIdentitySystemUser
        => _pluginManagedIdentitySystemUser.Value;

    public bool IsUserPluginManagedIdentitySystemUser
        => _isUserPluginManagedIdentitySystemUser.Value;

    public bool UserHasImpersonationPrivilege
        => _userHasImpersonationPrivilege.Value;

    public bool IsApplicationRequestingSelf
        => _isApplicationSelfRequest.Value;

    public bool IsRequestedApplicationPluginIdentity
        => _isPluginIdentityRequest.Value;

    public TokenCredential PluginAzureTokenCredential
        => field ??= new PowerPlatformFicTokenCredential(_serviceProvider);

    public ArmClient ArmClient
        => field ??= new ArmClient(PluginAzureTokenCredential);

    public ConfidentialClientApplicationOptions? ConfidentialClientApplicationOptions
        => _msalClientOptions.Value;

    public PluginClientCredentialsSource? ClientCredentialsSource
        => _clientCredentialsSource.Value;

    public KeyVaultDataAccessPermisions ClientCredentialsSourceAccessPermissions
        => _clientCredentialsSourceAccessPermissions.Value;

    public bool UserHasSufficientClientCredentialsSourceAccessPermission
        => _userHasSufficientClientCredentialsSourceAccessPermission.Value;

    private ManagedIdentity? RetrievePluginManagedIdentity()
    {
        var context = _serviceProvider.Get<IPluginExecutionContext>();
        IOrganizationService client = SystemDataverseClient;
        if (context.OwningExtension?.Id is not Guid sdkStepId) return null;
        SdkMessageProcessingStep? sdkStepEntity = client.Retrieve(
            context.OwningExtension?.LogicalName ??
            SdkMessageProcessingStep.EntityLogicalName,
            sdkStepId,
            SdkMessageProcessingStep.ColumnSet
            ) switch
        {
            SdkMessageProcessingStep s => s,
            Entity e => e.ToEntity<SdkMessageProcessingStep>(),
            _ => null,
        };
        EntityReference? pluginTypeRef = sdkStepEntity?.EventHandler
#pragma warning disable CS0612 // Type or member is obsolete
            ?? sdkStepEntity?.PluginTypeId
#pragma warning restore CS0612 // Type or member is obsolete
            ;
        if (pluginTypeRef is null ||
            !PluginType.EntityLogicalName.Equals(pluginTypeRef.LogicalName, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        PluginType? pluginTypeEntity = client.Retrieve(
            PluginType.EntityLogicalName,
            pluginTypeRef.Id,
            PluginType.ColumnSet
            ) switch
        {
            PluginType pt => pt,
            Entity e => e.ToEntity<PluginType>(),
            _ => null,
        };
        if (pluginTypeEntity?.PluginAssemblyId is not EntityReference pluginAssemblyRef)
        { return null; }
        PluginAssembly? pluginAssemblyEntity = client.Retrieve(
            pluginAssemblyRef.LogicalName ?? PluginAssembly.EntityLogicalName,
            pluginAssemblyRef.Id,
            PluginAssembly.ColumnSet
            ) switch
        {
            PluginAssembly pa => pa,
            Entity e => e.ToEntity<PluginAssembly>(),
            _ => null,
        };
        if (pluginAssemblyEntity is null) return null;
        if (pluginAssemblyEntity.ManagedIdentityId is null &&
            pluginAssemblyEntity.PackageId is EntityReference packageRef)
        {
            PluginPackage? pluginPackageEntity = client.Retrieve(
                packageRef.LogicalName ?? PluginPackage.EntityLogicalName,
                packageRef.Id,
                PluginPackage.ColumnSet
                ) switch
            {
                PluginPackage pp => pp,
                Entity e => e.ToEntity<PluginPackage>(),
                _ => null,
            };
            pluginAssemblyEntity.ManagedIdentityId =
                pluginPackageEntity?.managedidentityid;
        }
        if (pluginAssemblyEntity.ManagedIdentityId is not EntityReference managedIdentityRef)
        {
            return null;
        }
        ManagedIdentity? managedIdentityEntity = client.Retrieve(
            managedIdentityRef.LogicalName ?? ManagedIdentity.EntityLogicalName,
            managedIdentityRef.Id,
            ManagedIdentity.ColumnSet
            ) switch
        {
            ManagedIdentity mi => mi,
            Entity e => e.ToEntity<ManagedIdentity>(),
            _ => null,
        };
        return managedIdentityEntity;
    }

    private SystemUser? RetrievePluginManagedIdentitySystemUser()
    {
        if (PluginManagedIdentity is not { ApplicationId: Guid appId }) return null;
        IOrganizationService client = SystemDataverseClient;
        QueryExpression appUserQuery = new(SystemUser.EntityLogicalName)
        {
            TopCount = 2,
            ColumnSet = SystemUser.ApplicationUserColumnSet,
            Criteria =
            {
                Conditions =
                {
                    new(SystemUser.Fields.ApplicationId, ConditionOperator.Equal, appId),
                },
            },
        };
        EntityCollection appUserResults = client.RetrieveMultiple(appUserQuery);
        return appUserResults.TotalRecordCount != 0
            ? appUserResults.Entities.Single() switch
            {
                SystemUser su => su,
                Entity e => e.ToEntity<SystemUser>(),
                _ => null,
            }
            : null;
    }

    private SystemUser? RetrieveApplicationSystemUser()
    {
        var context = _serviceProvider.Get<IPluginExecutionContext7>();
        return context.IsApplicationUser
            ? SystemDataverseClient.Retrieve(
                SystemUser.EntityLogicalName,
                context.UserId,
                SystemUser.ApplicationUserColumnSet
                ) switch
            {
                SystemUser su => su,
                Entity e => e.ToEntity<SystemUser>(),
                _ => null,
            }
            : null;
    }

    private bool EvaluateIsUserSameAsPlugin()
    {
        var context = _serviceProvider.Get<IPluginExecutionContext7>();
        return context.IsApplicationUser &&
            context.UserId != Guid.Empty &&
            context.UserId == PluginManagedIdentitySystemUser?.SystemUserId;
    }

    private bool EvaluateUserHasImpersonationPrivilege()
    {
        var context = _serviceProvider.Get<IPluginExecutionContext>();
        RetrieveUserSetOfPrivilegesByNamesRequest privRequ = new()
        {
            UserId = context.UserId,
            PrivilegeNames = PrivilegeNamesImpersonation,
        };
        return DataverseClient.Execute(privRequ)
            is RetrieveUserSetOfPrivilegesByNamesResponse
        { RolePrivileges.Length: > 0 };
    }

    private ConfidentialClientApplicationOptions? ConstructConfidentialClientApplicationOptions()
    {
        const StringComparison cmp = StringComparison.OrdinalIgnoreCase;
        var context = _serviceProvider.Get<IPluginExecutionContext6>();
        var idpAuthorityInfo = _serviceProvider.Get<IEnvironmentService>();
        Uri idpInstanceUri = idpAuthorityInfo.AzureAuthorityHost;
        string idpInstanceUrl = idpInstanceUri.ToString();

        if (_inputs.TryGetValue(
            InputParameterNames.Application,
            out EntityReference applicationEntityReference))
        {
            return applicationEntityReference.LogicalName switch
            {
                string n when ManagedIdentity.EntityLogicalName.Equals(n, cmp)
                    => GetByEntityReference<ManagedIdentity>(
                        SystemDataverseClient,
                        applicationEntityReference,
                        ManagedIdentity.ColumnSet
                        ) switch
                        {
                            ManagedIdentity mi => ConstructFromManagedIdentity(mi),
                            null => null,
                        },
                string n when SystemUser.EntityLogicalName.Equals(n, cmp)
                    => GetByEntityReference<SystemUser>(
                        SystemDataverseClient,
                        applicationEntityReference,
                        SystemUser.ApplicationUserColumnSet
                        ) switch
                        {
                            SystemUser appUser => ConstructFromSystemUser(appUser),
                            null => null,
                        },
                string n when ApplicationUser.EntityLogicalName.Equals(n, cmp)
                    => GetByEntityReference<ApplicationUser>(
                        SystemDataverseClient,
                        applicationEntityReference,
                        ApplicationUser.ColumnSet
                        ) switch
                        {
                            ApplicationUser appUser => ConstructFromApplicationUser(appUser),
                            null => null,
                        },
                _ => throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Entity '{SystemUser.EntityLogicalName}' specified for {InputParameterNames.Application}, but only the following entities are allowed: {ManagedIdentity.EntityLogicalName}, {SystemUser.EntityLogicalName}, {ApplicationUser.EntityLogicalName}"
                    ),
            };

            static T? GetByEntityReference<T>(
                IOrganizationService dataverseClient,
                EntityReference r,
                ColumnSet columnSet
                ) where T : Entity
            {
                return dataverseClient.Retrieve(r.LogicalName, r.Id, columnSet) switch
                {
                    T t => t,
                    Entity e => e.ToEntity<T>(),
                    _ => null,
                };
            }
        }

        return ApplicationSystemUser is SystemUser user
            ? ConstructFromSystemUser(user)
            : null
            ;

        ConfidentialClientApplicationOptions ConstructFromManagedIdentity(
            ManagedIdentity managedIdentity
            )
        {
            ConfidentialClientApplicationOptions opts = new()
            {
                Instance = idpInstanceUrl,
                TenantId = (managedIdentity.TenantId switch
                {
                    Guid g => g != Guid.Empty ? g : context.TenantId,
                    null => context.TenantId,
                }).ToString(),
                ClientId = managedIdentity.ApplicationId?.ToString(),
                ClientName = managedIdentity.Name ?? managedIdentity.LogicalName,
            };
            if (managedIdentity.KeyVaultReferenceId is EntityReference miCreds &&
                (!_inputs.TryGetValue<EntityReference?>(
                    InputParameterNames.ClientCredentialsSource,
                    out var overrideCreds
                ) || overrideCreds is null))
            {
                _inputs[InputParameterNames.ClientCredentialsSource] =
                    miCreds;
            }
            return opts;
        }

        ConfidentialClientApplicationOptions ConstructFromSystemUser(SystemUser applicationUser)
        {
            if (applicationUser is not { ApplicationId: Guid appId })
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Entity '{SystemUser.EntityLogicalName}' specified for {InputParameterNames.Application}, but referenced entity does not represent an application user."
                    );
            }
            ConfidentialClientApplicationOptions opts = new()
            {
                Instance = idpInstanceUrl,
                TenantId = context.TenantId.ToString(),
                ClientId = appId.ToString(),
                ClientName = applicationUser.FullName,
            };
            return opts;
        }

        ConfidentialClientApplicationOptions ConstructFromApplicationUser(ApplicationUser applicationUser)
        {
            if (applicationUser is not { ApplicationId: Guid appId })
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Entity '{SystemUser.EntityLogicalName}' specified for {InputParameterNames.Application}, but referenced entity does not represent an application user."
                    );
            }
            ConfidentialClientApplicationOptions opts = new()
            {
                Instance = idpInstanceUrl,
                TenantId = context.TenantId.ToString(),
                ClientId = appId.ToString(),
                ClientName = applicationUser.ApplicationName,
            };
            return opts;
        }
    }

    private bool EvaluateIsApplicationSelfRequest()
    {
        var context = _serviceProvider.Get<IPluginExecutionContext6>();
        SystemUser? callingApplicationUser = ApplicationSystemUser;
        ConfidentialClientApplicationOptions? msalOptions =
            ConfidentialClientApplicationOptions;
        if (callingApplicationUser is not null &&
            msalOptions is not null &&
            string.Equals(
                callingApplicationUser.ApplicationId?.ToString(),
                msalOptions.ClientId,
                StringComparison.OrdinalIgnoreCase
                ) &&
            string.Equals(
                context.TenantId.ToString(),
                msalOptions.TenantId,
                StringComparison.OrdinalIgnoreCase
                ))
        {
            // Calling user and requested application identity are equal
            return true;
        }

        return false;
    }

    private bool EvaluateIsApplicationPluginIdentityRequest()
    {
        ManagedIdentity? pluginIdentity = PluginManagedIdentity;
        ConfidentialClientApplicationOptions? msalOptions =
            ConfidentialClientApplicationOptions;
        if (pluginIdentity is not null &&
            msalOptions is not null &&
            string.Equals(
                pluginIdentity.ApplicationId?.ToString(),
                msalOptions.ClientId,
                StringComparison.OrdinalIgnoreCase
                ) &&
            string.Equals(
                pluginIdentity.TenantId?.ToString(),
                msalOptions.TenantId,
                StringComparison.OrdinalIgnoreCase
                ))
        {
            // Plugin identity and requested application identity are equal
            return true;
        }

        return false;
    }

    private PluginClientCredentialsSource? ResolveClientCredentialsSource()
    {
        // Force evaluation of ConfidentialClientApplicationOptions to ensure
        // inferred client credentials source is written to input parameters.
        _ = ConfidentialClientApplicationOptions;

        PluginClientCredentialsSource clientCredentialsSource = new();
        if (clientCredentialsSource is not
            {
                KeyVaultUri: Uri kvUri
            })
        {
            return null;
        }

        clientCredentialsSource.KeyVaultName =
            kvUri.Host[..kvUri.Host.IndexOf('.')];
        ResolveClientCredentialsSourceAsync(clientCredentialsSource)
            .GetAwaiter().GetResult();
        switch (clientCredentialsSource.KeyVaultObjectType)
        {
            case keytype.Secret:

                break;
            case keytype.Certificate:
            case keytype.CertificateWithX5c:
                break;
        }
        return clientCredentialsSource;
    }

    private async Task ResolveClientCredentialsSourceAsync(
        PluginClientCredentialsSource clientCredentialsSource)
    {
        await ResolveKeyVaultResourceIdentifierAsync(clientCredentialsSource)
            .ConfigureAwait(continueOnCapturedContext: false);
    }

    private async Task ResolveKeyVaultResourceIdentifierAsync(
        PluginClientCredentialsSource clientCredentialsSource)
    {
        await foreach (SubscriptionResource azSub in ArmClient.GetSubscriptions()
            .ConfigureAwait(continueOnCapturedContext: false))
        {
            await foreach (KeyVaultResource keyVault in azSub.GetKeyVaultsAsync()
                .ConfigureAwait(continueOnCapturedContext: false))
            {
                if (keyVault.Data.Name.Equals(clientCredentialsSource.KeyVaultName, CmpOrdIgn))
                {
                    clientCredentialsSource.KeyVaultResourceIdentifier =
                        keyVault.Id;
                    return;
                }
            }
        }
    }

    private KeyVaultDataAccessPermisions EvaluateUserKeyVaultDataAccessPermissions()
    {
        PluginClientCredentialsSource? clientCredentialsSource =
            ClientCredentialsSource;
        if (clientCredentialsSource is not
            { KeyVaultObjectResourceIdentifier: ResourceIdentifier kvObjectResId})
            return KeyVaultDataAccessPermisions.None;

        var context = _serviceProvider.Get<IPluginExecutionContext2>();
        KeyVaultDataAccessEvaluator accessEvaluator = new(
            ArmClient,
            kvObjectResId,
            context.UserAzureActiveDirectoryObjectId
            );
        return accessEvaluator.EvaluateAccessAsync().GetAwaiter().GetResult();
    }

    private bool EvaluateUserHasSufficientKeyVaultDataAccessPermissions()
    {
        KeyVaultDataAccessPermisions effectivePermissions =
            ClientCredentialsSourceAccessPermissions;
        PluginClientCredentialsSource? clientCredentialsSource =
            ClientCredentialsSource;
        return clientCredentialsSource is not null && clientCredentialsSource.KeyVaultObjectType switch
        {
            keytype.Secret
            => effectivePermissions.HasFlag(KeyVaultDataAccessPermisions.GetSecret),
            keytype.Certificate or
            keytype.CertificateWithX5c
            => effectivePermissions.HasFlag(
                KeyVaultDataAccessPermisions.ReadCertificateProperties |
                KeyVaultDataAccessPermisions.SignWithKey),
            _ => false,
        };
    }
}
