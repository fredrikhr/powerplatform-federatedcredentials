using System.Text.Json;

using Microsoft.Crm.Sdk.Messages;

using System.IdentityModel.Tokens.Jwt;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public abstract class AccessTokenAcquisitionPluginBase : PluginBase
{
    internal static class OutputParameterNames
    {
        internal const string AccessToken = nameof(AccessToken);
        internal const string JsonWebToken = nameof(JsonWebToken);
    }

    protected static readonly JwtSecurityTokenHandler JwtHandler = new();

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1031: Do not catch general exception types",
        Justification = nameof(ITracingService)
        )]
    protected override void ExecuteCore(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();
        var outputs = context.OutputParameters;

        string accessToken = AcquireAccessToken(serviceProvider);;

        outputs[OutputParameterNames.AccessToken] = accessToken;

        try
        {
            outputs[OutputParameterNames.JsonWebToken] = GetJwtEntity(accessToken);
        }
        catch (Exception except)
        {
            var trace = serviceProvider.Get<ITracingService>();
            TraceException(trace, except);
        }
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
        return (dataverseResponse.RolePrivileges?.Length ?? 0) > 0;
    }
}