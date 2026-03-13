using Microsoft.PowerApps.CoreFramework.PowerPlatform.Api;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public sealed class OnBehalfOfTokenBundePlugin
    : PluginBase, IPlugin
{
    protected override void ExecuteCore(PluginContext context)
    {
        _ = context ?? throw new ArgumentNullException(nameof(context));
        ParameterCollection outputs = context.Outputs;
        IPluginExecutionContext6 execContext = context.ExecutionContext;
        var envService = context.ServiceProvider
            .Get<IInternalEnvironmentService>();
        var apiDiscovery = PowerPlatformApiDiscovery
            .FromClusterCategoryName(envService.ClusterCategory);
        var pwrfxSvc = context.ServiceProvider
            .GetPowerFxConnectorService();

        string tokenBundleUrl = $"https://{apiDiscovery.GetEnvironmentEndpoint(execContext.EnvironmentId)}/powerautomate/users/me/onBehalfOfTokenBundle?api-version=1";
        SafeHttpRequestMessage httpRequMsg = new(
            tokenBundleUrl,
            "POST",
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            body: string.Empty
            );
        SafeHttpResponse httpResp = pwrfxSvc.GetResponseUsingOboToken(httpRequMsg);
        outputs[nameof(httpResp.StatusCode)] = httpResp.StatusCode;
        outputs[nameof(httpResp.Body)] = httpResp.Body;
        AddHttpHeaderEntity(nameof(httpResp.Headers), httpResp.Headers, outputs);
        AddHttpHeaderEntity(nameof(httpResp.ContentHeaders), httpResp.ContentHeaders, outputs);
    }

    private static void AddHttpHeaderEntity(string name, IReadOnlyDictionary<string, string>? httpHeaders, ParameterCollection outputs)
    {
        if (httpHeaders is null) return;
        Entity httpHeadersEntity = new();
        foreach (var httpHeaderPair in httpHeaders)
        {
            httpHeadersEntity.Attributes[httpHeaderPair.Key] = httpHeaderPair.Value;
        }
        outputs[name] = httpHeadersEntity;
    }
}