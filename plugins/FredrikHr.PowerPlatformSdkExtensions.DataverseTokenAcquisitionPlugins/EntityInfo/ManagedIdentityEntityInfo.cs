using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins.EntityInfo;

using static ManagedIdentityEntityInfo.AttributeLogicalName;

internal static class ManagedIdentityEntityInfo
{
    internal static class AttributeLogicalName
    {
        internal const string ManagedIdentityId = "managedidentityid";
        internal const string TenantId = "tenantid";
        internal const string Name = "name";
        internal const string ApplicationId = "applicationid";
        internal const string CredentialSource = "credentialsource";
        internal const string KeyVaultReferenceId = "keyvaultreferenceid";
        internal const string Statecode = "statecode";
        internal const string Statuscode = "statuscode";
        internal const string VersionNumber = "versionnumber";
    }

    internal const string EntityLogicalName = "managedidentity";

    internal const int CredentialSourceKeyVaultOptionValue = 1;
    internal const int StatecodeActiveOptionValue = 0;

    internal static readonly ColumnSet ColumnSet = new(
        ManagedIdentityId,
        TenantId,
        Name,
        ApplicationId,
        CredentialSource,
        KeyVaultReferenceId,
        Statecode,
        Statuscode,
        VersionNumber
        );
}
