using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

partial class PluginAssembly
{
    public static ColumnSet ColumnSet { get; } = new([
        Fields.PluginAssemblyId,
        Fields.ManagedIdentityId,
        Fields.PackageId,
    ]);
}