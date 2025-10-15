using System.Text.Json;

using Microsoft.Crm.Sdk.Messages;

using System.IdentityModel.Tokens.Jwt;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins.EntityInfo;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public abstract class AccessTokenAcquisitionPluginBase : IPlugin
{
    static AccessTokenAcquisitionPluginBase()
    {
        PluginDependencyAssemblyLoader.DeregisterTracingService(default);
    }

    internal static class OutputParameterNames
    {
        internal const string AccessToken = nameof(AccessToken);
        internal const string JsonWebToken = "JsonWebToken";
    }

    protected static readonly JwtSecurityTokenHandler JwtHandler = new();

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1031: Do not catch general exception types",
        Justification = nameof(ITracingService)
        )]
    public void Execute(IServiceProvider serviceProvider)
    {
        var trace = serviceProvider.Get<ITracingService>();
        PluginDependencyAssemblyLoader.RegisterTracingService(trace);
        var context = serviceProvider.Get<IPluginExecutionContext>();
        var outputs = context.OutputParameters;

        string accessToken;
        try
        {
            accessToken = AcquireAccessToken(serviceProvider);
        }
        catch (InvalidPluginExecutionException except)
        {
            trace.Trace("{0}", except);
            throw;
        }
        catch (Exception except)
        {
            trace.Trace("{0}", except);
            throw new InvalidPluginExecutionException(
                message: except.Message,
                exception: except
                );
        }
        outputs[OutputParameterNames.AccessToken] = accessToken;

        try
        {
            outputs[OutputParameterNames.JsonWebToken] = GetJwtEntity(accessToken);
        }
        catch (Exception except)
        {
            trace.Trace("{0}", except);
        }

        PluginDependencyAssemblyLoader.DeregisterTracingService(trace);
    }

    private static Entity? GetJwtEntity(string? accessToken)
    {
        if (accessToken is null) return null;
        Entity jwtEntity = new();
        try
        {
            var jwt = JwtHandler.ReadJwtToken(accessToken);
            jwtEntity[nameof(jwt.Header)] = JwtDictionaryToEntity(jwt.Header);
            jwtEntity[nameof(jwt.Payload)] = JwtDictionaryToEntity(jwt.Payload);
            jwtEntity["Signature"] = jwt.RawSignature;
        }
        catch (ArgumentException argExcept)
        {
            Entity exceptEntity = new();
            exceptEntity[nameof(Type)] = argExcept.GetType().Name;
            exceptEntity[nameof(argExcept.Message)] = argExcept.Message;
            exceptEntity[nameof(argExcept.HResult)] = argExcept.HResult;
            jwtEntity[nameof(Exception)] = exceptEntity;
        }

        return jwtEntity;
    }

    private static Entity? JwtDictionaryToEntity(Dictionary<string, object?>? jwtDict)
    {
        if (jwtDict is null) return null;
        Entity jwtEntity = new();

        foreach (var jwtClaim in jwtDict)
        {
            object? jwtValue = jwtClaim.Value switch
            {
                JsonElement jsonElement => GetEntityAttributeValue(jsonElement),
                _ => jwtClaim.Value,
            };
            jwtEntity[jwtClaim.Key] = jwtValue;
        }

        return jwtEntity;

        static object? GetEntityAttributeValue(JsonElement jsonElement)
        {
            return jsonElement.ValueKind switch
            {
                JsonValueKind.Null => null,
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                JsonValueKind.String => jsonElement.GetString(),
                JsonValueKind.Number =>
                    jsonElement.TryGetInt32(out int jsonInt)
                    ? jsonInt
                    : jsonElement.TryGetInt64(out long jsonLong)
                    ? jsonLong
                    : jsonElement.GetDouble(),
                JsonValueKind.Array => GetEntityAttributeValueFromArray(jsonElement),
                JsonValueKind.Object => JwtDictionaryToEntity(jsonElement.Deserialize<Dictionary<string, object?>>()!),
                _ => jsonElement.Deserialize<Dictionary<string, object?>>(),
            };

            static object? GetEntityAttributeValueFromArray(JsonElement jsonElement)
            {
                object?[] jsonArray = new object?[jsonElement.GetArrayLength()];
                int jsonArrayIdx = 0;
                foreach (var jsonArrayElement in jsonElement.EnumerateArray())
                {
                    jsonArray[jsonArrayIdx] = GetEntityAttributeValue(jsonArrayElement);
                    jsonArrayIdx++;
                }
                return jsonArray;
            }
        }
    }

    protected abstract string AcquireAccessToken(IServiceProvider serviceProvider);

    protected static Entity? GetExecutingPluginManagedIdentityRecord(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();
        var dataverseService = serviceProvider.Get<IOrganizationServiceFactory>()
            .CreateOrganizationService(null);
        Entity sdkStepEntity = dataverseService.Retrieve(
            context.OwningExtension?.LogicalName!
            ?? SdkMessageProcessingStepEntityInfo.EntityLogicalName,
            context.OwningExtension?.Id ?? Guid.Empty,
            SdkMessageProcessingStepEntityInfo.ColumnSet
            );
        if (
            !sdkStepEntity.TryGetAttributeValue(
                SdkMessageProcessingStepEntityInfo.AttributeLogicalName.PluginTypeId,
                out EntityReference? pluginTypeEntityRef
                ) ||
                pluginTypeEntityRef is null
            )
        { return null; }

        Entity pluginTypeEntity = dataverseService.Retrieve(
            PluginTypeEntityInfo.EntityLogicalName,
            pluginTypeEntityRef.Id,
            PluginTypeEntityInfo.ColumnSet
            );
        if (
            !pluginTypeEntity.TryGetAttributeValue(
                PluginTypeEntityInfo.AttributeLogicalName.PluginAssemblyId,
                out EntityReference? pluginAssemblyEntityRef
                ) ||
            pluginAssemblyEntityRef is null
            )
        { return null; }

        Entity pluginAssemblyEntity = dataverseService.Retrieve(
            PluginAssemblyEntityInfo.EntityLogicalName,
            pluginAssemblyEntityRef.Id,
            PluginAssemblyEntityInfo.ColumnSet
            );
        if (
            pluginAssemblyEntity.TryGetAttributeValue(
                PluginAssemblyEntityInfo.AttributeLogicalName.ManagedIdentityId,
                out EntityReference? managedIdentityEntityRef
                ) &&
            managedIdentityEntityRef is not null
            )
        {
            return dataverseService.Retrieve(
                ManagedIdentityEntityInfo.EntityLogicalName,
                managedIdentityEntityRef.Id,
                ManagedIdentityEntityInfo.ColumnSet
                );
        }

        if (
            !pluginAssemblyEntity.TryGetAttributeValue(
                PluginAssemblyEntityInfo.AttributeLogicalName.PackageId,
                out EntityReference? pluginPackageEntityRef
                ) ||
            pluginPackageEntityRef is null
            )
        { return null; }

        Entity pluginPackageEntity = dataverseService.Retrieve(
            PluginPackageEntityInfo.EntityLogicalName,
            pluginPackageEntityRef.Id,
            PluginPackageEntityInfo.ColumnSet
            );
#pragma warning disable IDE0046 // Convert to conditional expression
        if (
            pluginPackageEntity.TryGetAttributeValue(
                PluginPackageEntityInfo.AttributeLogicalName.ManagedIdentityId,
                out managedIdentityEntityRef
                ) &&
                managedIdentityEntityRef is not null
            )
        {
            return dataverseService.Retrieve(
                ManagedIdentityEntityInfo.EntityLogicalName,
                managedIdentityEntityRef.Id,
                ManagedIdentityEntityInfo.ColumnSet
                );
        }
#pragma warning restore IDE0046 // Convert to conditional expression

        return null;
    }

    protected static bool TryGetUserApplicationId(
        IServiceProvider serviceProvider,
        out Guid applicationId)
    {
        var context = serviceProvider.Get<IPluginExecutionContext7>();
        if (context.IsApplicationUser)
        {
            IOrganizationService dataverseService = serviceProvider
                .Get<IOrganizationServiceFactory>()
                .CreateOrganizationService(null);
            Entity systemUserEntity = dataverseService.Retrieve(
                ApplicationSystemUserEntityInfo.EntityLogicalName,
                context.UserId,
                ApplicationSystemUserEntityInfo.ColumnSet
                );
            return systemUserEntity.TryGetAttributeValue(
                ApplicationSystemUserEntityInfo.AttributeLogicalName.ApplicationId,
                out applicationId
                );
        }
        applicationId = Guid.Empty;
        return false;
    }

    protected const string PrivilegeNameImpersonation = "prvActOnBehalfOfAnotherUser";
    private static readonly string[] PrivilegeNamesImpersonation = [PrivilegeNameImpersonation];

    protected static bool CheckUserHasImpersonatePrivilege(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.Get<IPluginExecutionContext2>();
        IOrganizationService dataverseService = serviceProvider
            .Get<IOrganizationServiceFactory>()
            .CreateOrganizationService(null);
        RetrieveAadUserSetOfPrivilegesByNamesRequest dataverseRequest = new()
        {
            DirectoryObjectId = context.UserAzureActiveDirectoryObjectId,
            PrivilegeNames = PrivilegeNamesImpersonation,
        };
        var dataverseResponse = (RetrieveAadUserSetOfPrivilegesByNamesResponse)
            dataverseService.Execute(dataverseRequest);
        foreach (RolePrivilege prv in dataverseResponse.RolePrivileges)
        {
            if (prv.BusinessUnitId == context.BusinessUnitId)
            {
                return true;
            }
        }

        return false;
    }
}