
namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public abstract class PluginBase : IPlugin
{
    static PluginBase()
    {
        PluginDependencyAssemblyLoader.DeregisterTracingService(null);
    }

    internal static void TraceException(ITracingService trace, Exception exception)
    {
        Stack<Exception> exceptions = [];
        for (Exception? exceptInst = exception; exceptInst is not null; exceptInst = exceptInst.InnerException)
        {
            exceptions.Push(exceptInst);
        }
        while (exceptions.Count > 0)
        {
            Exception exceptInst = exceptions.Pop();
            trace.Trace($"Unhandled during {nameof(Execute)}: {{0}}", exceptInst);
        }
    }

    public void Execute(IServiceProvider serviceProvider)
    {
        var trace = serviceProvider.Get<ITracingService>();
        PluginDependencyAssemblyLoader.RegisterTracingService(trace);
        try
        {
            ExecuteCore(serviceProvider);
        }
        catch (Exception except)
        when (except is not InvalidPluginExecutionException)
        {
            TraceException(trace, except);
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

    protected abstract void ExecuteCore(IServiceProvider serviceProvider);
}