using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

partial class ManagedIdentity
{
    public static ColumnSet ColumnSet { get; } = new([
        Fields.ManagedIdentityId,
        Fields.TenantId,
        Fields.Name,
        Fields.ApplicationId,
        Fields.CredentialSource,
        Fields.KeyVaultReferenceId,
        Fields.statecode,
        Fields.statuscode,
        Fields.VersionNumber
    ]);

    partial class Fields
    {
        internal const string TenantDomainName = "tenantdomainname";
    }
}