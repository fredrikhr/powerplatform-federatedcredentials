using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.EntityInfo;

using static SdkMessageProcessingStepEntityInfo.AttributeLogicalName;

internal static class SdkMessageProcessingStepEntityInfo
{
    internal static class AttributeLogicalName
    {
        internal const string PluginTypeId = "plugintypeid";
    }

    internal const string EntityLogicalName = "sdkmessageprocessingstep";

    internal static readonly ColumnSet ColumnSet = new(
        PluginTypeId
        );
}
