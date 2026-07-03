using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

partial class ManagedIdentity
{
    public static ColumnSet ColumnSet { get; } = new(allColumns: true);
}