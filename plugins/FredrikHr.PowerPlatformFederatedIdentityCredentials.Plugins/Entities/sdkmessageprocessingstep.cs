using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.Entities;

partial class SdkMessageProcessingStep
{
    public static ColumnSet ColumnSet { get; } = new([
        Fields.SdkMessageProcessingStepId,
        Fields.PluginTypeId
    ]);
}