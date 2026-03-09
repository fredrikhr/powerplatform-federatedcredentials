using System.Collections.Concurrent;

using Azure.Core;

using Microsoft.IdentityModel.JsonWebTokens;

namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

internal sealed class ManagedIdentityAzureCredential(
    IEnvironmentService azureAuthorityInfo,
    IAssemblyAuthenticationContext pluginAuthProvider,
    ITracingService? trace
    ) : TokenCredential
{
    private static readonly JsonWebTokenHandler JwtHandler = new();
    private readonly ConcurrentDictionary<string[], string> _accessTokens =
        new(AccessTokenScopesComparer.Instance);
    private static readonly ReadOnlyMemory<char> UriSchemeChars = "://".AsMemory();

    private readonly string _authorityInstanceUrl = azureAuthorityInfo.
        AzureAuthorityHost.ToString();

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

        string? firstScope = requestContext.Scopes?.FirstOrDefault();
        if (string.IsNullOrEmpty(firstScope))
            firstScope = "00000007-0000-0000-c000-000000000000/.default";
        int slashIdx = firstScope!.LastIndexOf('/');
        string resource = slashIdx > 2 &&
            !firstScope.AsSpan(slashIdx - 2, 3).SequenceEqual(UriSchemeChars.Span)
            ? firstScope[..slashIdx]
            : firstScope;
        try
        {
            accessToken = pluginAuthProvider.AcquireToken(
                _authorityInstanceUrl,
                resource,
                AuthenticationType.ManagedIdentity
                );
        }
        catch (Exception acquireTokenExcept)
        {
            trace?.Trace(
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