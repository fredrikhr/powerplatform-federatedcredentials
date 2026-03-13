namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

internal static class PowerFxServiceProvider
{
    internal static Type ConnectorServiceType { get; } = Type.GetType(
        "Microsoft.CDSRuntime.SandboxWorker.PowerFxConnectorServiceProvider" + ", " +
        "Microsoft.CDSRuntime.SandboxWorker, PublicKeyToken=31bf3856ad364e35",
        throwOnError: true
        );

    public static IPowerFxConnectorService GetPowerFxConnectorService(
        this IServiceProvider serviceProvider
        )
    {
        object sandboxCallbackService = serviceProvider.GetSandboxCallbackService();
        var pwrfxSvc = (IPowerFxConnectorService)Activator.CreateInstance(
            ConnectorServiceType,
            sandboxCallbackService
            );
        return pwrfxSvc;
    }
}
