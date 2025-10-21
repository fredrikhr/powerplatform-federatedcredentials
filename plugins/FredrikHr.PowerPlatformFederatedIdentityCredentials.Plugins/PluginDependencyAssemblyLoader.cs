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

            GetFilePathsFromThisAssembly(
                out string? locationDirectoryPath,
                out string? codeBaseDirectoryPath
                );
            if (locationDirectoryPath is not null)
            {
                filepath = Path.Combine(locationDirectoryPath, filename);
                yield return filepath;
            }
            if (codeBaseDirectoryPath is not null)
            {
                filepath = Path.Combine(codeBaseDirectoryPath, filename);
                yield return filepath;
            }

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

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1031: Do not catch general exception types",
        Justification = nameof(ResolveEventHandler)
        )]
    internal static void GetFilePathsFromThisAssembly(
        out string? locationDirectoryPath,
        out string? codeBaseDirectoryPath
        )
    {
        locationDirectoryPath = null;
        codeBaseDirectoryPath = null;
        Assembly thisAssembly = typeof(PluginDependencyAssemblyLoader).Assembly;
        try
        {
            if (!string.IsNullOrEmpty(thisAssembly.Location) &&
                File.Exists(thisAssembly.Location))
            {
                locationDirectoryPath = Path.GetDirectoryName(thisAssembly.Location);
            }
        }
        catch (Exception pathExcept)
        {
            s_trace?.Trace("While determining directory path for location of assembly: {0}", pathExcept);
            return;
        }

        try
        {
            if (!string.IsNullOrEmpty(thisAssembly.CodeBase) &&
                File.Exists(thisAssembly.CodeBase))
            {
                codeBaseDirectoryPath = Path.GetDirectoryName(thisAssembly.CodeBase);
            }
        }
        catch (Exception pathExcept)
        {
            s_trace?.Trace("While determining directory path for code base of assembly: {0}", pathExcept);
            return;
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

    internal static ITracingService? TracingService => s_trace;
}