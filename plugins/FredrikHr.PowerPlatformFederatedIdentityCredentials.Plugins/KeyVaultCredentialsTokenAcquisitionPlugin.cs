using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.Authorization;
using Azure.ResourceManager.Authorization.Models;
using Azure.ResourceManager.KeyVault;
using Azure.ResourceManager.Resources;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class KeyVaultCredentialsTokenAcquisitionPlugin
    : FederatedIdentityTokenAcquisitionPlugin, IPlugin
{
    protected override string AcquireSecondaryAccessToken(
        IServiceProvider serviceProvider,
        string tenantId,
        string clientId,
        IEnumerable<string> reqScopes
        )
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();
        ManagedIdentityAzureCredential tokenCredential = new(
            serviceProvider.Get<IManagedIdentityService>()
            );
        context.SharedVariables[nameof(TokenCredential)] = tokenCredential;

        throw new NotImplementedException();
    }

    private static void InitializeArmClient(
        IServiceProvider serviceProvider
        )
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();
        var tokenCredential = (TokenCredential)context
            .SharedVariables[nameof(TokenCredential)];

        ArmClientOptions armClientOptions = new();

        ArmClient armClient = new(tokenCredential, default, armClientOptions);
        context.SharedVariables[nameof(ArmClient)] = armClient;
    }

    private static string GetKeyVaultName(string keyVaultUri)
    {
        string keyVaultHost = new Uri(keyVaultUri).Host;
        return keyVaultHost[..keyVaultHost.IndexOf('.')];
    }

    private static async Task DetermineKeyVaultResourceIdentifierAsync(
        IServiceProvider serviceProvider,
        string keyVaultUrl
        )
    {
        const StringComparison cmp = StringComparison.OrdinalIgnoreCase;
        var context = serviceProvider.Get<IPluginExecutionContext>();
        var armClient = (ArmClient)context.SharedVariables[nameof(ArmClient)];
        string keyVaultName = GetKeyVaultName(keyVaultUrl);
        await foreach (SubscriptionResource subscription in armClient.GetSubscriptions().ConfigureAwait(continueOnCapturedContext: false))
        {
            await foreach (KeyVaultResource keyVault in subscription.GetKeyVaultsAsync().ConfigureAwait(continueOnCapturedContext: false))
            {
                if (keyVault.Data.Name.Equals(keyVaultName, cmp))
                {
                    context.SharedVariables[nameof(KeyVaultResource)] = keyVault;
                    return;
                }
            }
        }

        throw new InvalidPluginExecutionException(
            httpStatus: PluginHttpStatusCode.NotFound,
            message: $"Unable to find KeyVault resource from specified URL: {keyVaultUrl}"
            );
    }

    private static bool AllowsKeyVaultDataAction(
        AuthorizationRoleDefinitionResource roleDefinition,
        IEnumerable<string> requiredDataActions
        )
    {
        StringComparer cmp = StringComparer.OrdinalIgnoreCase;

        IList<RoleDefinitionPermission>? rolePermissions =
            roleDefinition?.Data?.Permissions;
        if (rolePermissions is null) return false;

        bool isGranted = false;
        bool isDenied = false;
        foreach (RoleDefinitionPermission rolePermission in roleDefinition?.Data?.Permissions ?? [])
        {
            isGranted |= ActionListContainsAny(rolePermission.DataActions, requiredDataActions);
            isDenied |= ActionListContainsAny(rolePermission.NotDataActions, requiredDataActions);

            if (isGranted && isDenied) break;
        }
        return isGranted && !isDenied;

        bool ActionListContainsAny(IList<string> actionsList, IEnumerable<string> comparands)
        {
            return actionsList.Any(action => comparands.Contains(action, cmp));


        }
    }
}