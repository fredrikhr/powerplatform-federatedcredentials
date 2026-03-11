using System.Collections.Concurrent;

using Microsoft.IdentityModel.JsonWebTokens;

using Azure.Core;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

internal sealed class ManagedIdentityAzureCredential(
    IServiceProvider serviceProvider
    ) : TokenCredential()
{
    private static readonly JsonWebTokenHandler JwtHandler = new();
    private readonly ConcurrentDictionary<string[], string> _accessTokens =
        new(AccessTokenScopesComparer.Instance);

    private readonly IManagedIdentityService _managedIdentity =
        serviceProvider.Get<IManagedIdentityService>();
    private readonly ITracingService _trace =
        serviceProvider.Get<ITracingService>();

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1031: Do not catch general exception types",
        Justification = nameof(ITracingService)
        )]
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

        try
        {
            accessToken = _managedIdentity.AcquireToken(
                requestContext.Scopes
                );
        }
        catch (Exception acquireTokenExcept)
        {
            _trace?.Trace(
                "Error while acquiring access token when using Azure SDK TokenCredential: {0}",
                acquireTokenExcept
                );
        }
        _accessTokens[requestContext.Scopes ?? []] = accessToken;
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
            JsonWebToken jwt = JwtHandler.ReadJsonWebToken(accessToken);
            expiration = new(jwt.ValidTo);
        }
        catch
        {
            expiration = DateTimeOffset.UtcNow.AddHours(1);
        }
        return new(accessToken, expiration);
    }
}