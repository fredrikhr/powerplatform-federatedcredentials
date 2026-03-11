using System.Reflection;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

internal sealed class PluginPackageManagedIdentityService
{
    private const string SandboxGrpcContractsAssemblyName =
        "Microsoft.CDSRuntime.SandboxGrpcContracts.Contracts, PublicKeyToken=31bf3856ad364e35";

    private static readonly Type ExecuteRequestTypeRef = Type.GetType(
        "CDSRunTime.Sandbox.Contract.PluginPackageManagedIdentityServiceProviderAcquireTokenRequest" + ", " +
        SandboxGrpcContractsAssemblyName,
        throwOnError: true
        );
    private static readonly Type ExecuteResponseTypeRef = Type.GetType(
        "CDSRunTime.Sandbox.Contract.ExecuteResponse" + ", " +
        SandboxGrpcContractsAssemblyName,
        throwOnError: true
        );
    private static readonly Type RequestDataOneofCaseTypeRef = Type.GetType(
        "CDSRunTime.Sandbox.Contract.ExecuteRequest+RequestDataOneofCase" + ", " +
        SandboxGrpcContractsAssemblyName,
        throwOnError: true
        );

    private static readonly System.Globalization.CultureInfo Inv =
        System.Globalization.CultureInfo.InvariantCulture;

    private static readonly object RequestDataOneofCase = Enum.Parse(
        RequestDataOneofCaseTypeRef,
        "PluginPackageManagedIdentityServiceProviderAcquireTokenResponse",
        ignoreCase: true
        );

    private readonly dynamic _sandboxCallbackService;

    public PluginPackageManagedIdentityService(
        IServiceProvider serviceProvider
        )
    {
        var fcs = serviceProvider.Get<IFeatureControlService>();
        _sandboxCallbackService = fcs.GetType().InvokeMember(
            "_sandboxCallbackService",
            BindingFlags.Public | BindingFlags.NonPublic |
            BindingFlags.Instance | BindingFlags.GetField,
            Type.DefaultBinder,
            target: fcs,
            args: null,
            culture: Inv
            );
    }

    public string AcquireToken(
        Guid managedIdentityId,
        IEnumerable<string> scopes
        )
    {
        object callbackArg = GetSandboxCallback(response =>
        {
            dynamic request = Activator.CreateInstance(ExecuteRequestTypeRef);
            request.ManagedIdentityId = managedIdentityId;
            IList<string> requestScopes = (IList<string>)request.Scopes;
            foreach (string requestedScope in scopes)
            { requestScopes.Add(requestedScope); }
            response.PluginPackageManagedIdentityServiceProviderAcquireTokenRequest = request;
            return RequestDataOneofCase;
        });
        dynamic request = _sandboxCallbackService.ExecuteCallBack(callbackArg);
        dynamic response = request.PluginPackageManagedIdentityServiceProviderAcquireTokenResponse;
        return (response.AccessToken as string)!;
    }

    private static readonly Func<Func<dynamic, object>, object> GetSandboxCallback =
        (Func<Func<dynamic, object>, object>)
        typeof(PluginPackageManagedIdentityService)
        .GetMethod(nameof(WrapCallback), BindingFlags.Static | BindingFlags.NonPublic)
        .MakeGenericMethod(
            ExecuteResponseTypeRef,
            RequestDataOneofCaseTypeRef
        ).CreateDelegate(typeof(Func<Func<dynamic, object>, object>));

    private static Func<TArg, TResult> WrapCallback<TArg, TResult>(
        Func<dynamic, object> callback
        ) where TArg : class
    {
        return TypedCallback;

        TResult TypedCallback(TArg arg)
        {
            return (TResult)callback(arg);
        }
    }
}