using System.Reflection;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

internal static class SandboxCallbackServiceProvider
{
    internal static Type SandboxCallbackServiceType { get; } = Type.GetType(
        "Microsoft.CDSRuntime.SandboxWorker.ISandboxCallbackService" + ", " +
        "Microsoft.CDSRuntime.SandboxWorker, PublicKeyToken=31bf3856ad364e35",
        throwOnError: true
        );

    internal static object GetSandboxCallbackService(
        this IServiceProvider serviceProvider
        )
    {
        var fcs = serviceProvider.Get<IFeatureControlService>();
        object sandboxCallbackService = fcs.GetType().InvokeMember(
            "_sandboxCallbackService",
            BindingFlags.Public | BindingFlags.NonPublic |
            BindingFlags.Instance | BindingFlags.GetField,
            Type.DefaultBinder,
            target: fcs,
            args: null,
            System.Globalization.CultureInfo.InvariantCulture
            );
        System.Diagnostics.Debug.Assert(SandboxCallbackServiceType
            .IsAssignableFrom(sandboxCallbackService.GetType())
            );
        return sandboxCallbackService;
    }
}