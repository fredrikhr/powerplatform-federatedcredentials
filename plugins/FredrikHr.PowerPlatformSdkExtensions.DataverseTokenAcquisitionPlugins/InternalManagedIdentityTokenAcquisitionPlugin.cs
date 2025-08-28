using System.Reflection;

namespace FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins;

public class InternalManagedIdentityTokenAcquisitionPlugin
    : AccessTokenAcquisitionPluginBase, IPlugin
{
    private const string TokenAcquirerTypeName =
        "Microsoft.Xrm.Sdk.IInternalManagedIdentityService, " +
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
        var scopes = context.InputParameterOrDefault<string[]>("Scopes");
        var tenant = context.InputParameterOrDefault<string?>("TenantId");
        if (string.IsNullOrEmpty(tenant))
        {
            tenant = serviceProvider.Get<IPluginExecutionContext6>()
                .TenantId.ToString();
        }

        try
        {
            return TokenAcquirerType.InvokeMember(
                "AcquireTokenFromTenant",
                BindingFlags.Instance |
                BindingFlags.Public |
                BindingFlags.InvokeMethod,
                Type.DefaultBinder,
                tokenAcquirer,
                args: [scopes, tenant],
                System.Globalization.CultureInfo.InvariantCulture
                ) as string ?? throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.InternalServerError,
                    message: "Token acquisition method returned a null-valued access token."
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
