[assembly: Microsoft.Xrm.Sdk.Client.ProxyTypesAssembly()]

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

using System.Xml;

using Lock = Object;

internal static class ProxyTypesAssemblyRegistrar
{
    private static readonly Lock SyncLock = new();
    private static bool s_isRegistered;

    internal static void EnsureProxyTypesRegistered()
    {
        lock (SyncLock)
        {
            if (s_isRegistered) return;

            PerformProxyTypeRegistration();
            s_isRegistered = true;
        }
    }

    private static void PerformProxyTypeRegistration()
    {
        KnownTypesResolver knownTypesResolver = new();
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
            knownTypesResolver.ResolvedTypes[derivedEntityType.Name] = entityXmlTuple;
        }
    }
}