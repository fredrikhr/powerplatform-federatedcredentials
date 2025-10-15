using System.Net.Http;
using System.Text.Json;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.EntityInfo;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class RetrieveRequestedManagedIdentityPlugin()
    : PluginBase(ExecuteInternal), IPlugin
{
    internal static class InputParameterNames
    {
        internal const string TenantId = nameof(TenantId);
        internal const string ApplicationId = nameof(ApplicationId);
        internal const string Name = nameof(Name);
    }

    internal static class OutputParameterNames
    {
        internal const string RequestedManagedIdentity = nameof(RequestedManagedIdentity);
    }

    internal static void ExecuteInternal(IServiceProvider serviceProvider)
    {
        const StringComparison cmp = StringComparison.OrdinalIgnoreCase;
        var context = serviceProvider.Get<IPluginExecutionContext>();
        Entity? managedIdentity = null;
        if (ManagedIdentityEntityInfo.EntityLogicalName.Equals(context.PrimaryEntityName, cmp))
        {
            var dataverseService = serviceProvider.Get<IOrganizationServiceFactory>()
                .CreateOrganizationService(default);
            managedIdentity = dataverseService.Retrieve(
                context.PrimaryEntityName,
                context.PrimaryEntityId,
                ManagedIdentityEntityInfo.ColumnSet
                );
        }

        if (managedIdentity is null)
        {
            managedIdentity = new(ManagedIdentityEntityInfo.EntityLogicalName);
            if (context.InputParameters.TryGetValue(InputParameterNames.TenantId, out Guid tenantId))
            {
                managedIdentity[ManagedIdentityEntityInfo.AttributeLogicalName.TenantId] =
                    tenantId;
            }
            else if (context.InputParameters.TryGetValue(InputParameterNames.TenantId, out string tenantDomainName))
            {
                if (!Guid.TryParse(tenantDomainName, out tenantId))
                {
                    managedIdentity[ManagedIdentityEntityInfo.AttributeLogicalName.TenantDomainName] =
                        tenantDomainName;

                    tenantId = ResolveTenantIdFromDomainNameAsync(serviceProvider, tenantDomainName)
                        .GetAwaiter().GetResult();
                }

                managedIdentity[ManagedIdentityEntityInfo.AttributeLogicalName.TenantId] =
                    tenantId;
            }

            if (context.InputParameters.TryGetValue(InputParameterNames.ApplicationId, out Guid applicationId))
            {
                managedIdentity[ManagedIdentityEntityInfo.AttributeLogicalName.ApplicationId] =
                    applicationId;
            }

            if (context.InputParameters.TryGetValue(InputParameterNames.Name, out string name))
            {
                managedIdentity[ManagedIdentityEntityInfo.AttributeLogicalName.Name] = name;
            }
        }

        context.OutputParameters[OutputParameterNames.RequestedManagedIdentity] =
            managedIdentity;
    }

    private static async Task<Guid> ResolveTenantIdFromDomainNameAsync(
        IServiceProvider serviceProvider,
        string tenantDomainName
        )
    {
        using HttpClient httpClient = new();
        Uri instanceUri = serviceProvider.Get<IEnvironmentService>().AzureAuthorityHost;
        Uri oidcConfigUri = await
            GetTenantDiscoveryEndpointAsync(httpClient, instanceUri, tenantDomainName)
            .ConfigureAwait(continueOnCapturedContext: false);
        using Stream oidcConfigStream = await httpClient
            .GetStreamAsync(oidcConfigUri)
            .ConfigureAwait(continueOnCapturedContext: false);
        using JsonDocument oidcConfigJson = await JsonDocument
            .ParseAsync(oidcConfigStream)
            .ConfigureAwait(continueOnCapturedContext: false);
        Uri oidcIssuerUri = new(
            oidcConfigJson.RootElement.GetProperty("issuer").GetString(),
            UriKind.Absolute
            );
        _ = Guid.TryParse(oidcIssuerUri.Segments[1].TrimEnd('/'), out Guid tenantId);
        return tenantId;

        static async Task<Uri> GetTenantDiscoveryEndpointAsync(
            HttpClient httpClient,
            Uri instanceUri,
            string tenantDomainName
            )
        {
            Uri mockAuthorizationEndpointUri = new(
                instanceUri,
                $"/{Uri.EscapeUriString(tenantDomainName)}/oauth2/v2.0/authorize"
                );
            Uri instanceDiscoveryUri = new(
                instanceUri,
                $"/common/discovery/instance?api-version=1.0&authorization_endpoint={Uri.EscapeDataString(mockAuthorizationEndpointUri.ToString())}"
                );
            using Stream instaceDiscoveryStream = await httpClient
                .GetStreamAsync(instanceDiscoveryUri)
                .ConfigureAwait(continueOnCapturedContext: false);
            using JsonDocument instanceDiscovery = await JsonDocument
                .ParseAsync(instaceDiscoveryStream)
                .ConfigureAwait(continueOnCapturedContext: false);
            Uri oidcConfigUri = new(
                instanceDiscoveryUri,
                instanceDiscovery.RootElement.GetProperty("tenant_discovery_endpoint").GetString()
                );
            return oidcConfigUri;
        }
    }
}