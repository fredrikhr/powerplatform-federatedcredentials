using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins.EntityInfo;

using static KeyVaultReferenceEntityInfo.AttributeLogicalName;

internal static class KeyVaultReferenceEntityInfo
{
    internal static class AttributeLogicalName
    {
        internal const string KeyVaultReferenceId = "keyvaultreferenceid";
        internal const string KeyVaultUri = "keyvaulturi";
        internal const string KeyName = "keyname";
        internal const string KeyType = "keytype";
        internal const string Statecode = "statecode";
        internal const string Statuscode = "statuscode";
        internal const string VersionNumber = "versionnumber";
    }

    internal const string EntityLogicalName = "keyvaultreference";
    internal static readonly ColumnSet ColumnSet = new(
        KeyVaultReferenceId,
        KeyVaultUri,
        KeyName,
        KeyType,
        Statecode,
        Statuscode,
        VersionNumber
        );
}