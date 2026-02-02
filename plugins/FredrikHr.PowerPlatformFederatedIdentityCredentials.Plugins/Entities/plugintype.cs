using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

partial class PluginType
{
    public static ColumnSet ColumnSet { get; } = new([
        Fields.PluginAssemblyId
    ]);
}