using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins.EntityInfo;

using static PluginTypeEntityInfo.AttributeLogicalName;

internal static class PluginTypeEntityInfo
{
    internal static class AttributeLogicalName
    {
        internal const string PluginAssemblyId = "pluginassemblyid";
    }

    internal const string EntityLogicalName = "plugintype";

    internal static readonly ColumnSet ColumnSet = new(
        PluginAssemblyId
        );
}
