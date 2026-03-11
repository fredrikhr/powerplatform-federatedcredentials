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
        internal const string Scopes = nameof(Scopes);
    }

    protected override string AcquireAccessToken(PluginContext pluginContext)
    {
        IPluginExecutionContext execContext = pluginContext.ExecutionContext;
        ParameterCollection inputs = pluginContext.Inputs;

        string managedIdentityId;
        if (ManagedIdentity.EntityLogicalName.Equals(execContext.PrimaryEntityName, Cmp))
        {
            managedIdentityId = execContext.PrimaryEntityId.ToString();
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

        if (!inputs.TryGetValue(
            InputParameterNames.Scopes,
            out string[] scopes) ||
            scopes is not { Length: > 0 }
            )
        {
            scopes = ["00000007-0000-0000-c000-000000000000/.default"];
        }

        Guid managedIdentityEntityId = Guid.Parse(managedIdentityId);
        IOrganizationService dataverseClient = pluginContext.DefaultDataverseClient;
        ManagedIdentity managedIdentityEntity = dataverseClient.Retrieve(
            ManagedIdentity.EntityLogicalName,
            managedIdentityEntityId,
            ManagedIdentity.ColumnSet
            ).ToEntity<ManagedIdentity>();
        bool userIsSameAsRequested = pluginContext.UserApplicationId.HasValue &&
            pluginContext.UserApplicationId == managedIdentityEntity.ApplicationId &&
            (
                !managedIdentityEntity.TenantId.HasValue ||
                pluginContext.ExecutionContext.TenantId == managedIdentityEntity.TenantId
            );
        if (!userIsSameAsRequested && !pluginContext.UserHasImpersonationPrivilege)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.Forbidden,
                message: $"Entra Object ID {pluginContext.ExecutionContext.UserAzureActiveDirectoryObjectId} is missing privilege {PluginContext.PrivilegeNameImpersonation}."
                );
        }

        IServiceProvider serviceProvider = pluginContext.ServiceProvider;
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
            IList<string> requestScopes = (IList<string>)request.Scopes;
            foreach (string requestedScope in scopes)
            { requestScopes.Add(requestedScope); }
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