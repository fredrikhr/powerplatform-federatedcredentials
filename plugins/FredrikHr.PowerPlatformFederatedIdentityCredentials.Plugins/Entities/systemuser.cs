using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

partial class SystemUser
{
    public static ColumnSet ApplicationSystemUserColumnSet { get; } = new([
        Fields.SystemUserId,
        Fields.ApplicationId,
    ]);
}