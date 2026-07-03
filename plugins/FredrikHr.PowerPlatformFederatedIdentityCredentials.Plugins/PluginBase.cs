namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public abstract class PluginBase : IPlugin
{
    internal static void TraceException(
        ITracingService trace,
        Exception exception,
        [System.Runtime.CompilerServices.CallerMemberName()]
        string? memberName = default
        )
    {
        Stack<Exception> exceptions = [];
        for (Exception? exceptInst = exception; exceptInst is not null; exceptInst = exceptInst.InnerException)
        {
            exceptions.Push(exceptInst);
        }
        while (exceptions.Count > 0)
        {
            Exception exceptInst = exceptions.Pop();
            trace.Trace($"Unhandled during {memberName ?? nameof(Execute)}: {{0}}", exceptInst);
        }
    }

    public void Execute(IServiceProvider serviceProvider)
    {
        var trace = serviceProvider.Get<ITracingService>();
        using PluginDependencyAssemblyLoader assemblyLoader = new(trace);
        assemblyLoader.PreloadAssemblies();
        ProxyTypesAssemblyRegistrar.EnsureProxyTypesRegistered();
        if (
            serviceProvider.Get<IOrganizationServiceFactory>()
            is IProxyTypesAssemblyProvider proxyTypesAssemblyProvider
            )
        {
            try
            {
                proxyTypesAssemblyProvider.ProxyTypesAssembly =
                    typeof(ProxyTypesAssemblyRegistrar).Assembly;
            }
            catch (Exception registrationExcept)
            when (registrationExcept is not InvalidPluginExecutionException)
            {
                TraceException(trace, registrationExcept);
            }
        }
        try
        {
            PluginExecutionInformation info = new(serviceProvider);
            ExecuteCore(serviceProvider, info);
        }
        catch (Exception except)
        when (except is not InvalidPluginExecutionException)
        {
            TraceException(trace, except);
            throw;
        }
    }

    protected abstract void ExecuteCore(
        IServiceProvider serviceProvider,
        PluginExecutionInformation info
        );
}