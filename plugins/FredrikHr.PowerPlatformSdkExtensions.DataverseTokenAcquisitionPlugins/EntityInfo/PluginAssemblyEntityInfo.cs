using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins.EntityInfo;

using static PluginAssemblyEntityInfo.AttributeLogicalName;

internal static class PluginAssemblyEntityInfo
{
    internal static class AttributeLogicalName
    {
        internal const string ManagedIdentityId = "managedidentityid";
        internal const string PackageId = "packageid";
    }

    internal const string EntityLogicalName = "pluginassembly";

    internal static readonly ColumnSet ColumnSet = new(
        ManagedIdentityId,
        PackageId
        );
}
