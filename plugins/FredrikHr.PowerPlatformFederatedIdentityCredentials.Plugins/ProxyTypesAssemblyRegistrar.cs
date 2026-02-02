[assembly: Microsoft.Xrm.Sdk.Client.ProxyTypesAssembly()]

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

using System.Runtime.Serialization;
using System.Xml;

using Lock = Object;

internal static class ProxyTypesAssemblyRegistrar
{
    private const string KnownTypesResolverTypeName =
        "Microsoft.Xrm.Sdk.KnownTypesResolver, " +
        "Microsoft.Xrm.Sdk, PublicKeyToken=31bf3856ad364e35";

    private static readonly Lock SyncLock = new();
    private static bool IsRegistered;

    internal static void EnsureProxyTypesRegistered(ITracingService trace)
    {
        lock (SyncLock)
        {
            if (IsRegistered) return;

            PerformProxyTypeRegistration(trace);
            IsRegistered = true;
        }
    }

    private static void PerformProxyTypeRegistration(ITracingService trace)
    {
        Type knownTypesResolverType = Type.GetType(
            KnownTypesResolverTypeName,
            throwOnError: true
            );
        var knownTypesResolver = (DataContractResolver)Activator.CreateInstance(
            knownTypesResolverType
            );
        var resolvedTypes = (IDictionary<string, Tuple<XmlDictionaryString, XmlDictionaryString>>)
            knownTypesResolverType.InvokeMember(
                "ResolvedTypes",
                System.Reflection.BindingFlags.Public |
                System.Reflection.BindingFlags.Instance |
                System.Reflection.BindingFlags.GetProperty,
                Type.DefaultBinder,
                target: knownTypesResolver,
                args: default,
                culture: System.Globalization.CultureInfo.InvariantCulture
                );
        _ = knownTypesResolver.TryResolveType(
            typeof(Entity),
            typeof(Entity),
            null,
            out XmlDictionaryString entityXmlTypeName,
            out XmlDictionaryString entityXmlNamespace
            );
        IEnumerable<Type> derivedEntityTypes = typeof(ProxyTypesAssemblyRegistrar)
            .Assembly.GetTypes()
            .Where(t => typeof(Entity).IsAssignableFrom(t));
        var entityXmlTuple = Tuple.Create(entityXmlTypeName, entityXmlNamespace);
        foreach (Type derivedEntityType in derivedEntityTypes)
        {
            resolvedTypes[derivedEntityType.Name] = entityXmlTuple;
            trace.Trace(
                "{0}.ResolvedTypes[{1}] = ({2}, {3})",
                knownTypesResolverType.Name,
                derivedEntityType.Name,
                entityXmlTuple.Item1,
                entityXmlTuple.Item2
                );
        }
    }
}