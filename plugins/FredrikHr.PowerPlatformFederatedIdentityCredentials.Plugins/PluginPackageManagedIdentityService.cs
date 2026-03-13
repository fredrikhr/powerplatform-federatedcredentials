using System.Reflection;

using CDSRunTime.Sandbox.Contract;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

internal sealed class PluginPackageManagedIdentityService(
    IServiceProvider serviceProvider
    ) : IPluginPackageManagedIdentityService
{
    private static readonly MethodInfo ExecuteCallBackMethodInfo =
        SandboxCallbackServiceProvider.SandboxCallbackServiceType.GetMethod(
            "ExecuteCallBack",
            BindingFlags.Instance | BindingFlags.Public,
            Type.DefaultBinder,
            [typeof(Func<,>).MakeGenericType(
                typeof(ExecuteResponse),
                typeof(ExecuteRequest.RequestDataOneofCase)
            )],
            modifiers: default
        );

    private readonly object _sandboxCallbackService = serviceProvider
        .GetSandboxCallbackService();

    public string AcquireToken(
        string managedIdentityId,
        IEnumerable<string> scopes
        )
    {
        Func<ExecuteResponse, ExecuteRequest.RequestDataOneofCase> callbackArg =
            OnCallback;
        var request = (ExecuteRequest)ExecuteCallBackMethodInfo.Invoke(
            _sandboxCallbackService,
            [callbackArg]
            );
        PluginPackageManagedIdentityServiceProviderAcquireTokenResponse response =
            request.PluginPackageManagedIdentityServiceProviderAcquireTokenResponse;
        return response.AccessToken!;

        ExecuteRequest.RequestDataOneofCase OnCallback(ExecuteResponse response)
        {
            PluginPackageManagedIdentityServiceProviderAcquireTokenRequest request = new()
            {
                ManagedIdentityId = managedIdentityId,
            };
            request.Scopes.AddRange(scopes);
            response.PluginPackageManagedIdentityServiceProviderAcquireTokenRequest = request;
            return ExecuteRequest.RequestDataOneofCase.PluginPackageManagedIdentityServiceProviderAcquireTokenResponse;
        }
    }

    public string AcquireToken(
        Guid managedIdentityId,
        IEnumerable<string> scopes
        ) => AcquireToken(managedIdentityId.ToString(), scopes);

    public string AcquireTokenFromTenant(
        string managedIdentityId,
        IEnumerable<string> scopes,
        string tenant
        )
    {
        Func<ExecuteResponse, ExecuteRequest.RequestDataOneofCase> callbackArg =
            OnCallback;
        var request = (ExecuteRequest)ExecuteCallBackMethodInfo.Invoke(
            _sandboxCallbackService,
            [callbackArg]
            );
        PluginPackageManagedIdentityServiceProviderAcquireTokenFromTenantResponse response =
            request.PluginPackageManagedIdentityServiceProviderAcquireTokenFromTenantResponse;
        return response.AccessToken!;

        ExecuteRequest.RequestDataOneofCase OnCallback(ExecuteResponse response)
        {
            PluginPackageManagedIdentityServiceProviderAcquireTokenFromTenantRequest request = new()
            {
                ManagedIdentityId = managedIdentityId,
            };
            request.Scopes.AddRange(scopes);
            response.PluginPackageManagedIdentityServiceProviderAcquireTokenFromTenantRequest = request;
            return ExecuteRequest.RequestDataOneofCase.PluginPackageManagedIdentityServiceProviderAcquireTokenFromTenantResponse;
        }
    }

    public string AcquireTokenFromTenant(
        Guid managedIdentityId,
        IEnumerable<string> scopes,
        string tenant
        ) => AcquireTokenFromTenant(managedIdentityId.ToString(), scopes, tenant);

    public string AcquireTokenFromTenant(
        Guid managedIdentityId,
        IEnumerable<string> scopes,
        Guid tenantId
        ) => AcquireTokenFromTenant(managedIdentityId.ToString(), scopes, tenantId.ToString());
}