using System.Reflection;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

internal sealed class PluginDependencyAssemblyLoader : IDisposable
{
    private readonly ITracingService _trace;
    private readonly ResolveEventHandler _resolveEventHandler;

    public PluginDependencyAssemblyLoader(
        ITracingService trace
        )
    {
        _trace = trace;
        _resolveEventHandler = PluginExecutionRuntimeAssemblyResolve;

        AppDomain.CurrentDomain.AssemblyResolve +=
            _resolveEventHandler;
    }

    public void Dispose()
    {
        AppDomain.CurrentDomain.AssemblyResolve -=
            _resolveEventHandler;
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1031: Do not catch general exception types",
        Justification = nameof(ResolveEventHandler)
        )]
    private Assembly PluginExecutionRuntimeAssemblyResolve(
        object sender,
        ResolveEventArgs args
        )
    {
        ITracingService trace = _trace;
        if (string.IsNullOrEmpty(args.Name)) return null!;
        Assembly? loadedAssembly;
        try
        {
            AssemblyName name = new(args.Name);
            string filename = $"{name.Name}.dll";

            foreach (string filepath in GetPossibleFilepaths(filename, trace))
            {
                if (File.Exists(filepath))
                {
                    loadedAssembly = Assembly.LoadFile(filepath);
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

        static IEnumerable<string> GetPossibleFilepaths(
            string filename,
            ITracingService trace
            )
        {
            string filepath;

            GetFilePathsFromThisAssembly(
                trace,
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
    private static void GetFilePathsFromThisAssembly(
        ITracingService trace,
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
            trace.Trace("While determining directory path for location of assembly: {0}", pathExcept);
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
            trace.Trace("While determining directory path for code base of assembly: {0}", pathExcept);
            return;
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1031: Do not catch general exception types",
        Justification = nameof(ITracingService)
        )]
    internal void PreloadAssemblies()
    {
        const string publicKeyToken = "PublicKeyToken=92742159e12e44c8";
        const string asmSys_CM = $"System.ClientModel, {publicKeyToken}";
        const string asmSys_MD = $"System.Memory.Data, PublicKeyToken=cc7b13ffcd2ddd51";
        const string asmAz_C = $"Azure.Core, {publicKeyToken}";
        const string asmAz_S_Kv_S = $"Azure.Security.KeyVault.Secrets, {publicKeyToken}";
        const string asmAz_S_Kv_C = $"Azure.Security.KeyVault.Certificates, {publicKeyToken}";
        const string asmAz_S_Kv_K = $"Azure.Security.KeyVault.Keys, {publicKeyToken}";
        const string asmAz_RM = $"Azure.ResourceManager, {publicKeyToken}";
        const string asmAz_RM_Authz = $"Azure.ResourceManager.Authorization, {publicKeyToken}";
        const string asmAz_RM_Kv = $"Azure.ResourceManager.KeyVault, {publicKeyToken}";

        /*
        GetFilePathsFromThisAssembly(_trace,
            out string? path1,
            out string? path2
            );
        List<string> paths = new(capacity: 2);
        if (!string.IsNullOrEmpty(path1))
            paths.Add(path1!);
        if (!string.IsNullOrEmpty(path2) && !path2!.Equals(path1, StringComparison.OrdinalIgnoreCase))
            paths.Add(path2);
        foreach (string path in paths)
        {
            foreach (string dllPath in Directory.EnumerateFiles(path, "*.dll"))
            {
                try
                {
                    _trace.Trace("Preloading assembly: {0}", dllPath);
                    Assembly.LoadFile(dllPath);
                }
                catch (Exception assemblyLoadExcept)
                {
                    PluginBase.TraceException(_trace, assemblyLoadExcept);
                }
            }
        }
        */

        try
        {
            Assembly.Load(asmSys_CM);
            Assembly.Load(asmSys_MD);
            Assembly.Load(asmAz_C);
            Assembly.Load(asmAz_S_Kv_S);
            Assembly.Load(asmAz_S_Kv_C);
            Assembly.Load(asmAz_S_Kv_K);
            Assembly.Load(asmAz_RM);
            Assembly.Load(asmAz_RM_Authz);
            Assembly.Load(asmAz_RM_Kv);
        }
        catch (Exception assemblyLoadExcept)
        {
            PluginBase.TraceException(_trace, assemblyLoadExcept);
        }
    }
}