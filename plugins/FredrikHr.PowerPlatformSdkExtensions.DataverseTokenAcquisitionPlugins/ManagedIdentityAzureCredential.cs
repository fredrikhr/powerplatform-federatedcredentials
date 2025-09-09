using System.IdentityModel.Tokens.Jwt;

using Azure.Core;

namespace FredrikHr.PowerPlatformSdkExtensions.DataverseTokenAcquisitionPlugins;

internal class ManagedIdentityAzureCredential(
    IManagedIdentityService managedIdentityService
    ) : TokenCredential
{
    private static readonly JwtSecurityTokenHandler JwtHandler = new();

    public override AccessToken GetToken(
        TokenRequestContext requestContext,
        CancellationToken cancellationToken
        )
    {
        string accessToken = managedIdentityService.AcquireToken(
            requestContext.Scopes
            );
        return CreateAccessTokenRecord(accessToken);
    }

    public override ValueTask<AccessToken> GetTokenAsync(
        TokenRequestContext requestContext,
        CancellationToken cancellationToken
        )
    {
        string accessToken = managedIdentityService.AcquireToken(
            requestContext.Scopes
            );
        return new(CreateAccessTokenRecord(accessToken));
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