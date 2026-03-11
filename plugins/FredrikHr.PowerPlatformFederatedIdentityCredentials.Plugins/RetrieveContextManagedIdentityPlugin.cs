namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class RetrieveContextManagedIdentityPlugin : PluginBase, IPlugin
{
    internal static class OutputParameterNames
    {
        internal const string PluginAssemblyManagedIdentity = nameof(PluginAssemblyManagedIdentity);
    }

    protected override void ExecuteCore(PluginContext context)
    {
        _ = context ?? throw new ArgumentNullException(nameof(context));
        context.Outputs[OutputParameterNames.PluginAssemblyManagedIdentity] =
            context.PluginManagedIdentity;
    }
}