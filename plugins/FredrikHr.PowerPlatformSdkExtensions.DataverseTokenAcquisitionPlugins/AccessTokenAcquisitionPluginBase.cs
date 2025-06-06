using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

namespace FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins;

public abstract class AccessTokenAcquisitionPluginBase : IPlugin
{
    private static readonly JwtSecurityTokenHandler jwtHandler = new();

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1031: Do not catch general exception types",
        Justification = nameof(ITracingService)
        )]
    public void Execute(IServiceProvider serviceProvider)
    {
        var trace = serviceProvider.Get<ITracingService>();
        var context = serviceProvider.Get<IPluginExecutionContext>();
        var outputs = context.OutputParameters;

        string accessToken;
        try
        {
            accessToken = AcquireAccessToken(serviceProvider);
        }
        catch (InvalidPluginExecutionException) { throw; }
        catch (Exception except)
        {
            throw new InvalidPluginExecutionException(
                message: except.Message,
                exception: except
                );
        }
        outputs["AccessToken"] = accessToken;

        try
        {
            outputs["JsonWebToken"] = GetJwtEntity(accessToken);
        }
        catch (Exception except)
        {
            trace.Trace("{0}", except);
        }
    }

    private static Entity? GetJwtEntity(string? accessToken)
    {
        if (accessToken is null) return null;
        Entity jwtEntity = new();
        try
        {
            var jwt = jwtHandler.ReadJwtToken(accessToken);
            jwtEntity[nameof(jwt.Header)] = ToEntity(jwt.Header);
            jwtEntity[nameof(jwt.Payload)] = ToEntity(jwt.Payload);
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

    private static Entity? ToEntity(Dictionary<string, object?>? jwtDict)
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
                JsonValueKind.Object => ToEntity(jsonElement.Deserialize<Dictionary<string, object?>>()!),
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
}