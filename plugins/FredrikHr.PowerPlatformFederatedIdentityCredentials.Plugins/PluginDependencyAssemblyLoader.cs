using System.Reflection;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

internal static class PluginDependencyAssemblyLoader
{
    private static volatile ITracingService? s_trace;

    static PluginDependencyAssemblyLoader()
    {
        AppDomain.CurrentDomain.AssemblyResolve +=
            PluginExecutionRuntimeAssemblyResolve;
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1031: Do not catch general exception types",
        Justification = nameof(ResolveEventHandler)
        )]
    private static Assembly PluginExecutionRuntimeAssemblyResolve(
        object sender,
        ResolveEventArgs args
        )
    {
        if (string.IsNullOrEmpty(args.Name)) return null!;
        Assembly? loadedAssembly;
        try
        {
            AssemblyName name = new(args.Name);
            string filename = $"{name.Name}.dll";

            foreach (string filepath in GetPossibleFilepaths(filename))
            {
                if (File.Exists(filepath))
                {
                    loadedAssembly = Assembly.LoadFile(filepath);
                    ITracingService? trace = s_trace;
                    try
                    {
                        trace?.Trace(
                            "Requested assembly '{0}' -> loaded assembly '{1}' from path '{2}'.",
                            name,
                            loadedAssembly.GetName(),
                            filepath
                            );
                    }
                    catch (Exception)
                    {
                        // Ignore exception from trace on purpose
                    }
                    return loadedAssembly;
                }
            }
        }
        catch (Exception) { return null!; }

        return null!;

        static IEnumerable<string> GetPossibleFilepaths(string filename)
        {
            string filepath;

            filepath = Path.Combine(Environment.CurrentDirectory, filename);
            yield return filepath;

            string cultureDirectory = System.Globalization.CultureInfo.CurrentCulture.Name;
            filepath = Path.Combine(Environment.CurrentDirectory, cultureDirectory, filename);
            yield return filepath;

            cultureDirectory = "en-US";
            filepath = Path.Combine(Environment.CurrentDirectory, cultureDirectory, filename);
            yield return filepath;
        }
    }

    internal static void RegisterTracingService(ITracingService trace)
    {
        s_trace = trace;
    }

    internal static void DeregisterTracingService(ITracingService? trace)
    {
        Interlocked.CompareExchange(ref s_trace, null, trace);
    }
}