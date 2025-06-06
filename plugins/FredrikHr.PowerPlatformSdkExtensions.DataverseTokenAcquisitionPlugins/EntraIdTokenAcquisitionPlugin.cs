namespace FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins;

public class EntraIdTokenAcquisitionPlugin
    : AccessTokenAcquisitionPluginBase, IPlugin
{
    protected override string AcquireAccessToken(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.Get<IPluginExecutionContext6>();
        var outputs = context.OutputParameters;

        var tokenAcquirer = serviceProvider.Get<ITokenService>()
            ?? throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.InternalServerError,
                message: $"{nameof(ITokenService)} instance is not available."
                );
        return tokenAcquirer.RetrieveAADAccessToken(
            context.InputParameterOrDefault<string>("ClientId"),
            context.InputParameterOrDefault<string>("ResourceId"),
            context.InputParameterOrDefault<string?>("TenantId") switch
            {
                { Length: > 0 } tenantId => tenantId,
                _ => context.TenantId.ToString()
            });
    }
}