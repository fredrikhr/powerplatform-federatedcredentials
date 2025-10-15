using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.EntityInfo;

using static PluginPackageEntityInfo.AttributeLogicalName;

internal static class PluginPackageEntityInfo
{
    internal static class AttributeLogicalName
    {
        internal const string ManagedIdentityId = "managedidentityid";
    }

    internal const string EntityLogicalName = "pluginpackage";

    internal static readonly ColumnSet ColumnSet = new(
        ManagedIdentityId
        );
}