using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;

using Azure.Core;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

internal sealed class ManagedIdentityAzureCredential(
    IManagedIdentityService managedIdentityService
    ) : TokenCredential
{
    private static readonly JwtSecurityTokenHandler JwtHandler = new();
    private readonly ConcurrentDictionary<string[], string> _accessTokens =
        new(AccessTokenScopesComparer.Instance);

    public override AccessToken GetToken(
        TokenRequestContext requestContext,
        CancellationToken cancellationToken
        )
    {
        if (_accessTokens.TryGetValue(requestContext.Scopes, out string accessToken))
        {
            AccessToken accessTokenRecord = CreateAccessTokenRecord(accessToken);
            if (accessTokenRecord.ExpiresOn.AddMinutes(-5) > DateTimeOffset.UtcNow)
                return accessTokenRecord;
        }

        accessToken = managedIdentityService.AcquireToken(
            requestContext.Scopes
            );
        _accessTokens[requestContext.Scopes] = accessToken;
        return CreateAccessTokenRecord(accessToken);
    }

    public override ValueTask<AccessToken> GetTokenAsync(
        TokenRequestContext requestContext,
        CancellationToken cancellationToken
        )
    {
        return new(GetToken(requestContext, cancellationToken));
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1031: Do not catch general exception types"
        )]
    private static AccessToken CreateAccessTokenRecord(string accessToken)
    {
        DateTimeOffset expiration;
        try
        {
            JwtSecurityToken jwt = JwtHandler.ReadJwtToken(accessToken);
            expiration = new(jwt.ValidTo);
        }
        catch
        {
            expiration = DateTimeOffset.UtcNow.AddHours(1);
        }
        return new(accessToken, expiration);
    }
}