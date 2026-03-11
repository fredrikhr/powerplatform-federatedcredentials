using System.Text.Json;

using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.JsonWebTokens;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

public abstract class AccessTokenAcquisitionPluginBase : PluginBase
{
    internal static class OutputParameterNames
    {
        internal const string AccessToken = nameof(AccessToken);
        internal const string JsonWebToken = nameof(JsonWebToken);
    }

    protected static readonly JwtSecurityTokenHandler JwtRawHandler = new();
    protected static readonly JsonWebTokenHandler JwtHandler = new();

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1031: Do not catch general exception types",
        Justification = nameof(ITracingService)
        )]
    protected override void ExecuteCore(PluginContext context)
    {
        _ = context ?? throw new ArgumentNullException(nameof(context));
        var outputs = context.Outputs;

        string accessToken = AcquireAccessToken(context);

        outputs[OutputParameterNames.AccessToken] = accessToken;

        try
        {
            outputs[OutputParameterNames.JsonWebToken] = GetJwtEntity(accessToken);
        }
        catch (Exception except)
        {
            IServiceProvider serviceProvider = context.ServiceProvider;
            var trace = serviceProvider.Get<ITracingService>();
            TraceException(trace, except);
        }
    }

    internal static Entity? GetJwtEntity(string? accessToken)
    {
        if (accessToken is null) return null;
        Entity jwtEntity = new();
        try
        {
            var jwt = JwtRawHandler.ReadJwtToken(accessToken);
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
                bool allItemsString = true;
                foreach (var jsonArrayElement in jsonElement.EnumerateArray())
                {
                    object? jsonArrayItemValue = GetEntityAttributeValue(jsonArrayElement);
                    jsonArray[jsonArrayIdx] = jsonArrayItemValue;
                    allItemsString &= jsonArrayItemValue is string ||
                        jsonArrayItemValue is null;

                    jsonArrayIdx++;
                }
                return (allItemsString && jsonArray.Length > 0)
                    ? Array.ConvertAll(jsonArray, o => o as string)
                    : jsonArray;
            }
        }
    }

    protected abstract string AcquireAccessToken(PluginContext pluginContext);
}