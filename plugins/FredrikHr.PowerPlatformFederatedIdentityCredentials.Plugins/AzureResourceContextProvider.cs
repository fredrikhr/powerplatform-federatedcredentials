using Azure.Core;
using Azure.ResourceManager;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

internal static class AzureResourceContextProvider
{
    internal static TokenCredential GetOrCreateTokenCredential(
        IServiceProvider serviceProvider
        )
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();
        if (context.SharedVariables.TryGetValue(
            nameof(TokenCredential),
            out TokenCredential tokenCredential))
        {
            return tokenCredential;
        }

        tokenCredential = new ManagedIdentityAzureCredential(
            serviceProvider.Get<IManagedIdentityService>()
            );
        context.SharedVariables[nameof(TokenCredential)] = tokenCredential;
        return tokenCredential;
    }

    internal static ArmClient GetOrCreateArmClient(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();
        if (context.SharedVariables.TryGetValue(nameof(ArmClient), out ArmClient armClient))
        {
            return armClient;
        }

        TokenCredential tokenCredential = GetOrCreateTokenCredential(serviceProvider);
        ArmClientOptions armClientOptions = new();
        armClient = new(tokenCredential, default, armClientOptions);
        context.SharedVariables[nameof(ArmClient)] = armClient;
        return armClient;
    }
}