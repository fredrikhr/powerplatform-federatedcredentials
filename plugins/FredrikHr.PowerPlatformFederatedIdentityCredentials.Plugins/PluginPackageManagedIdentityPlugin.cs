using System.Reflection;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public sealed class PluginPackageManagedIdentityPlugin
    : AccessTokenAcquisitionPluginBase, IPlugin
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
    private const StringComparison Cmp = StringComparison.OrdinalIgnoreCase;

    internal static class InputParameterNames
    {
        internal const string ManagedIdentityId = nameof(ManagedIdentityId);
    }

    protected override string AcquireAccessToken(
        IServiceProvider serviceProvider
        )
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();
        ParameterCollection inputs = context.InputParameters;

        string managedIdentityId;
        if (ManagedIdentity.EntityLogicalName.Equals(context.PrimaryEntityName, Cmp))
        {
            managedIdentityId = context.PrimaryEntityId.ToString();
        }
        else if (inputs.TryGetValue(
            "Target",
            out EntityReference? entityReference) &&
            entityReference is { Id: Guid entityRefId }
            )
        {
            managedIdentityId = entityRefId.ToString();
        }
        else if (inputs.TryGetValue(
            InputParameterNames.ManagedIdentityId,
            out entityRefId
            ))
        {
            managedIdentityId = entityRefId.ToString();
        }
        else if (!inputs.TryGetValue(
            InputParameterNames.ManagedIdentityId,
            out managedIdentityId) ||
            string.IsNullOrEmpty(managedIdentityId))
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing or empty required input parameter: {InputParameterNames.ManagedIdentityId}"
                );
        }

        var fcs = serviceProvider.Get<IFeatureControlService>();
        dynamic sandboxCallbackSvc = fcs.GetType().InvokeMember(
            "_sandboxCallbackService",
            BindingFlags.Public | BindingFlags.NonPublic |
            BindingFlags.Instance | BindingFlags.GetField,
            Type.DefaultBinder,
            target: fcs,
            args: null,
            culture: Inv
            );
        object callbackArg = GetSandboxCallback(response =>
        {
            dynamic request = Activator.CreateInstance(ExecuteRequestTypeRef);
            request.ManagedIdentityId = managedIdentityId;
            response.PluginPackageManagedIdentityServiceProviderAcquireTokenRequest = request;
            return Enum.Parse(
                RequestDataOneofCaseTypeRef,
                "PluginPackageManagedIdentityServiceProviderAcquireTokenResponse",
                ignoreCase: true
                );
        });
        dynamic request = sandboxCallbackSvc.ExecuteCallBack(callbackArg);
        dynamic response = request.PluginPackageManagedIdentityServiceProviderAcquireTokenResponse;
        return (response.AccessToken as string)!;
    }

    private static readonly Func<Func<dynamic, object>, object> GetSandboxCallback =
        (Func<Func<dynamic, object>, object>)
        typeof(PluginPackageManagedIdentityPlugin)
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