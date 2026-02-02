using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

partial class KeyVaultReference
{
    partial class Fields
    {
        internal const string KeyVersion = "keyversion";
        internal const string KeyVaultResourceIdentifier = "resourceidentifier";
    }

    public static ColumnSet ColumnSet { get; } = new([
        Fields.KeyVaultReferenceId,
        Fields.KeyVaultUri,
        Fields.KeyName,
        Fields.KeyType,
        Fields.statecode,
        Fields.statuscode,
        Fields.VersionNumber,
    ]);
}