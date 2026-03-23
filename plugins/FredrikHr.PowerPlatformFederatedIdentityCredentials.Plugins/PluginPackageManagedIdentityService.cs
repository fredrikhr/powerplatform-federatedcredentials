using System.Reflection;

using Google.Protobuf.Collections;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

internal sealed class PluginPackageManagedIdentityService(
    IServiceProvider serviceProvider
    )
{
    private const string CdsRuntimeSandboxGrpcContractsAssembly =
        "Microsoft.CDSRuntime.SandboxGrpcContracts.Contracts, Culture=neutral, PublicKeyToken=31bf3856ad364e35";
    private static readonly Type ExecuteResponseType = Type.GetType(
        "CDSRunTime.Sandbox.Contract.ExecuteResponse" + ", " +
        CdsRuntimeSandboxGrpcContractsAssembly,
        throwOnError: true
        );
    private static readonly Type ExecuteRequestRequestDataOneofCaseType = Type.GetType(
        "CDSRunTime.Sandbox.Contract.ExecuteRequest+RequestDataOneofCase" + ", " +
        CdsRuntimeSandboxGrpcContractsAssembly,
        throwOnError: true
        );
    private static readonly Type PluginPackageManagedIdentityServiceProviderAcquireTokenRequestType = Type.GetType(
        "CDSRunTime.Sandbox.Contract.PluginPackageManagedIdentityServiceProviderAcquireTokenRequest" + ", " +
        CdsRuntimeSandboxGrpcContractsAssembly,
        throwOnError: true
        );
    private static readonly Type PluginPackageManagedIdentityServiceProviderAcquireTokenFromTenantRequestType = Type.GetType(
        "CDSRunTime.Sandbox.Contract.PluginPackageManagedIdentityServiceProviderAcquireTokenFromTenantRequest" + ", " +
        CdsRuntimeSandboxGrpcContractsAssembly,
        throwOnError: true
        );
    private static readonly object PluginPackageManagedIdentityServiceProviderAcquireTokenResponseCaseType = Enum.Parse(
        ExecuteRequestRequestDataOneofCaseType,
        "PluginPackageManagedIdentityServiceProviderAcquireTokenResponse",
        ignoreCase: true
        );
    private static readonly object PluginPackageManagedIdentityServiceProviderAcquireTokenFromTenantResponseCaseType = Enum.Parse(
        ExecuteRequestRequestDataOneofCaseType,
        "PluginPackageManagedIdentityServiceProviderAcquireTokenFromTenantResponse",
        ignoreCase: true
        );

    private static readonly Type ExecuteCallBackArgumentType = typeof(Func<,>)
        .MakeGenericType(
            ExecuteResponseType,
            ExecuteRequestRequestDataOneofCaseType
            );

    private static readonly MethodInfo ExecuteCallBackMethodInfo =
        SandboxCallbackServiceProvider.SandboxCallbackServiceType.GetMethod(
            "ExecuteCallBack",
            BindingFlags.Instance | BindingFlags.Public,
            Type.DefaultBinder,
            [ExecuteCallBackArgumentType],
            modifiers: default
        );

    private readonly object _sandboxCallbackService = serviceProvider
        .GetSandboxCallbackService();

    private static readonly Func<Func<dynamic, object>, object> WrapCallbackImpl =
        (Func<Func<dynamic, object>, object>)
        typeof(PluginPackageManagedIdentityService)
        .GetMethod(
            nameof(WrapCallback),
            BindingFlags.Static | BindingFlags.NonPublic
            )
        .MakeGenericMethod(
            ExecuteResponseType,
            ExecuteRequestRequestDataOneofCaseType
            )
        .CreateDelegate(typeof(Func<Func<dynamic, object>, object>));

    private static object WrapCallback<TArg, TReturn>(
        Func<dynamic, object> callback
        ) where TArg : class
        where TReturn : struct, Enum
    {
        Func<TArg, TReturn> wrappedCallbackDelegate = CallbackWrapper;
        return wrappedCallbackDelegate;

        TReturn CallbackWrapper(TArg arg1)
        {
            return (TReturn)callback(arg1);
        }
    }

    public string AcquireToken(
        string managedIdentityId,
        IEnumerable<string> scopes
        )
    {
        object callbackArg = WrapCallbackImpl(OnCallback);
        dynamic request = ExecuteCallBackMethodInfo.Invoke(
            _sandboxCallbackService,
            [callbackArg]
            );
        dynamic response =
            request.PluginPackageManagedIdentityServiceProviderAcquireTokenResponse;
        return (string)response.AccessToken;

        object OnCallback(dynamic response)
        {
            dynamic request = Activator.CreateInstance(
                PluginPackageManagedIdentityServiceProviderAcquireTokenRequestType
                );
            request.ManagedIdentityId = managedIdentityId;
            var requestScopes = (RepeatedField<string>)request.Scopes;
            requestScopes.AddRange(scopes);
            response.PluginPackageManagedIdentityServiceProviderAcquireTokenRequest = request;
            return PluginPackageManagedIdentityServiceProviderAcquireTokenResponseCaseType;
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
        object callbackArg = WrapCallbackImpl(OnCallback);
        dynamic request = ExecuteCallBackMethodInfo.Invoke(
            _sandboxCallbackService,
            [callbackArg]
            );
        dynamic response =
            request.PluginPackageManagedIdentityServiceProviderAcquireTokenFromTenantResponse;
        return (string)response.AccessToken;

        object OnCallback(dynamic response)
        {
            dynamic request = Activator.CreateInstance(
                PluginPackageManagedIdentityServiceProviderAcquireTokenFromTenantRequestType
                );
            request.ManagedIdentityId = managedIdentityId;
            var requestScopes = (RepeatedField<string>)request.Scopes;
            requestScopes.AddRange(scopes);
            response.PluginPackageManagedIdentityServiceProviderAcquireTokenFromTenantRequest = request;
            return PluginPackageManagedIdentityServiceProviderAcquireTokenFromTenantResponseCaseType;
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