using System.Reflection;

namespace FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins;

public class PluginPackageManagedIdentityTokenAcquisitionPlugin :
    AccessTokenAcquisitionPluginBase, IPlugin
{
    private const string TokenAcquirerTypeName =
        "Microsoft.Xrm.Sdk.IPluginPackageManagedIdentityService, " +
        "Microsoft.Xrm.Kernel.Contracts.Internal, PublicKeyToken=31bf3856ad364e35";

    private static readonly Type? TokenAcquirerType = Type.GetType(
        TokenAcquirerTypeName,
        throwOnError: false
        );

    protected override string AcquireAccessToken(IServiceProvider serviceProvider)
    {
        if (TokenAcquirerType is null)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.InternalServerError,
                message: "Unable to load plugin execution service by assembly qualified name: " +
                    TokenAcquirerTypeName
                );
        }

        var tokenAcquirer = serviceProvider?.GetService(TokenAcquirerType)
            ?? throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.InternalServerError,
                message: $"{TokenAcquirerType} instance is not available."
                );

        var context = serviceProvider.Get<IPluginExecutionContext>();
        const string entityLogicalName = "managedidentity";
        if (!entityLogicalName.Equals(context.PrimaryEntityName, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Plugin execution bound to invalid entity '{context.PrimaryEntityName}'. Expected '{entityLogicalName}'."
                );
        }
        string managedidentityId = context.PrimaryEntityId.ToString();
        var scopes = context.InputParameterOrDefault<string[]>("Scopes");
        var tenant = context.InputParameterOrDefault<string?>("TenantId");
        string tokenAcquisitionMethod;
        object[] tokenAcquisitionArgs;
        if (string.IsNullOrEmpty(tenant))
        {
            tokenAcquisitionMethod = "AcquireToken";
            tokenAcquisitionArgs = [managedidentityId, scopes];
        }
        else
        {
            tokenAcquisitionMethod = "AcquireTokenFromTenant";
            tokenAcquisitionArgs = [managedidentityId, scopes, tenant!];
        }

        try
        {
            return TokenAcquirerType.InvokeMember(
                tokenAcquisitionMethod,
                BindingFlags.Instance |
                BindingFlags.Public |
                BindingFlags.InvokeMethod,
                Type.DefaultBinder,
                tokenAcquirer,
                tokenAcquisitionArgs,
                System.Globalization.CultureInfo.InvariantCulture
                ) as string ?? throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.InternalServerError,
                    message: "Token acquisition method return a null-valued access token."
                );
        }
        catch (TargetInvocationException invokeExcept)
        when (invokeExcept.InnerException is Exception except)
        {
            serviceProvider.Get<ITracingService>()?.Trace("{0}", except);
            throw except;
        }
    }
}