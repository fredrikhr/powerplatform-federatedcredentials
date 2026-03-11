using System.Net.Http;
using System.Text.Json;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class RetrieveRequestedManagedIdentityPlugin : PluginBase, IPlugin
{
    internal static class InputParameterNames
    {
        internal const string ManagedIdentityId = nameof(ManagedIdentityId);
        internal const string TenantId = nameof(TenantId);
        internal const string ApplicationId = nameof(ApplicationId);
        internal const string Name = nameof(Name);
    }

    internal static class OutputParameterNames
    {
        internal const string RequestedManagedIdentity = nameof(RequestedManagedIdentity);
    }

    protected override void ExecuteCore(PluginContext context)
    {
        _ = context ?? throw new ArgumentNullException(nameof(context));
        context.Outputs[OutputParameterNames.RequestedManagedIdentity] =
            context.RequestedManagedIdentity;
    }

    internal static void ExecuteInternal(
        PluginContext pluginContext,
        ParameterCollection? outputs = null
        )
    {
        outputs ??= pluginContext.Outputs;
        const StringComparison cmp = StringComparison.OrdinalIgnoreCase;
        IServiceProvider serviceProvider = pluginContext.ServiceProvider;
        IPluginExecutionContext context = pluginContext.ExecutionContext;
        ManagedIdentity? managedIdentity = null;
        if (ManagedIdentity.EntityLogicalName.Equals(context.PrimaryEntityName, cmp))
        {
            var dataverseService = pluginContext.DefaultDataverseClient;
            managedIdentity = dataverseService.Retrieve(
                context.PrimaryEntityName,
                context.PrimaryEntityId,
                ManagedIdentity.ColumnSet
                ).ToEntity<ManagedIdentity>();
        }
        if (((pluginContext.Inputs.TryGetValue(
            InputParameterNames.ManagedIdentityId,
            out string? managedIdentityIdString
            ) && Guid.TryParse(
                managedIdentityIdString,
                out Guid managedIdentityId)
            ) ||
            pluginContext.Inputs.TryGetValue(
            InputParameterNames.ManagedIdentityId,
            out managedIdentityId)) &&
            managedIdentityId != Guid.Empty
            )
        {
            var dataverseService = pluginContext.DefaultDataverseClient;
            managedIdentity = dataverseService.Retrieve(
                ManagedIdentity.EntityLogicalName,
                managedIdentityId,
                ManagedIdentity.ColumnSet
                ).ToEntity<ManagedIdentity>();
        }

        if (managedIdentity is null)
        {
            managedIdentity = new();
            if (pluginContext.Inputs.TryGetValue(InputParameterNames.TenantId, out Guid tenantId))
            {
                managedIdentity.TenantId = tenantId;
            }
            else if (pluginContext.Inputs.TryGetValue(InputParameterNames.TenantId, out string tenantDomainName))
            {
                if (!Guid.TryParse(tenantDomainName, out tenantId))
                {
                    managedIdentity[ManagedIdentity.Fields.TenantDomainName] =
                        tenantDomainName;

                    tenantId = ResolveTenantIdFromDomainNameAsync(serviceProvider, tenantDomainName)
                        .GetAwaiter().GetResult();
                }

                managedIdentity.TenantId = tenantId;
            }

            if (pluginContext.Inputs.TryGetValue(InputParameterNames.ApplicationId, out Guid applicationId))
            {
                managedIdentity.ApplicationId = applicationId;
            }

            if (pluginContext.Inputs.TryGetValue(InputParameterNames.Name, out string name))
            {
                managedIdentity.Name = name;
            }
        }

        outputs[OutputParameterNames.RequestedManagedIdentity] =
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