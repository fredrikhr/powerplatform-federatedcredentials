using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

partial class PluginPackage
{
    public static ColumnSet ColumnSet { get; } = new([
        Fields.managedidentityid,
    ]);
}