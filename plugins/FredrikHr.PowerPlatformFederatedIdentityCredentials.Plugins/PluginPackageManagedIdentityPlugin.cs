using System.Reflection;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public sealed class PluginPackageManagedIdentityPlugin
    : AccessTokenAcquisitionPluginBase, IPlugin
{
    internal static class InputParameterNames
    {
        internal const string ManagedIdentityId = nameof(ManagedIdentityId);
        internal const string Scopes = nameof(Scopes);
    }

    protected override string AcquireAccessToken(PluginContext pluginContext)
    {
        ParameterCollection inputs = pluginContext.Inputs;

        if (
            pluginContext.RequestedManagedIdentity
            is not { ManagedIdentityId: Guid managedIdentityId }
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing or empty required input parameter: {InputParameterNames.ManagedIdentityId}"
                );
        }

        if (!inputs.TryGetValue(
            InputParameterNames.Scopes,
            out string[] scopes) ||
            scopes is not { Length: > 0 }
            )
        {
            scopes = ["00000007-0000-0000-c000-000000000000/.default"];
        }

        PluginPackageManagedIdentityService managedIdentityService = new(
            pluginContext.ServiceProvider
            );
        return managedIdentityService.AcquireToken(
            managedIdentityId,
            scopes
            );
    }
}