using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

partial class PluginAssembly
{
    public static ColumnSet ColumnSet { get; } = new([
        Fields.ManagedIdentityId,
        Fields.PackageId,
    ]);
}