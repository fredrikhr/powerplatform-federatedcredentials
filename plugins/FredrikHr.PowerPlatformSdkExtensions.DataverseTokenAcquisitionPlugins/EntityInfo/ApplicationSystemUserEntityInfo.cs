using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins.EntityInfo;

using static ApplicationSystemUserEntityInfo.AttributeLogicalName;

internal static class ApplicationSystemUserEntityInfo
{
    internal static class AttributeLogicalName
    {
        internal const string SystemUserId = "systemuserid";
        internal const string ApplicationId = "applicationid";
    }

    internal const string EntityLogicalName = "systemuser";
    internal static readonly ColumnSet ColumnSet = new(
        SystemUserId,
        ApplicationId
        );
}