using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public class ResolveUserApplicationIdPlugin : PluginBase, IPlugin
{
    internal static class OutputParameterName
    {
        internal const string UserApplicationId = nameof(UserApplicationId);
    }

    protected override void ExecuteCore(PluginContext context)
    {
        _ = context ?? throw new ArgumentNullException(nameof(context));
        context.Outputs[OutputParameterName.UserApplicationId] =
            context.UserApplicationId;
    }
}