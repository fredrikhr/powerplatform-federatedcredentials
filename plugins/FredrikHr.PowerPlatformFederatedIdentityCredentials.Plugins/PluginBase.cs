
namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public abstract class PluginBase(Action<IServiceProvider> executeAction) : IPlugin
{
    static PluginBase()
    {
        PluginDependencyAssemblyLoader.DeregisterTracingService(null);
    }

    public void Execute(IServiceProvider serviceProvider)
    {
        var trace = serviceProvider.Get<ITracingService>();
        PluginDependencyAssemblyLoader.RegisterTracingService(trace);
        try
        {
            executeAction?.Invoke(serviceProvider);
        }
        catch (Exception except)
        when (except is not InvalidPluginExecutionException)
        {
            trace.Trace($"Unhandled during {nameof(Execute)}: {{0}}", except);
            throw;
        }
        finally
        {
            PluginDependencyAssemblyLoader.DeregisterTracingService(trace);
        }

        var context = serviceProvider.Get<IPluginExecutionContext>();
        List<string> nonSerializableVariableNames = [
            .. context.SharedVariables
            .Where((variable) => !IsSerializable(variable.Value))
            .Select((variable) => variable.Key)
            ];
        foreach (string variableName in nonSerializableVariableNames)
        {
            context.SharedVariables.Remove(variableName);
        }

        static bool IsSerializable(object variable) => variable switch
        {
            string => true,
            null => true,
            not null when variable.GetType().IsPrimitive => true,
            Entity or EntityCollection => true,
            Guid => true,
            OptionSetValue or OptionSetValueCollection => true,
            string[] or IEnumerable<string> => true,
            _ => false,
        };
    }
}