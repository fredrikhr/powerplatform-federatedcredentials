namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

internal sealed class AccessTokenScopesComparer() : IEqualityComparer<string[]>
{
    internal static AccessTokenScopesComparer Instance { get; } = new();

    public bool Equals(string[] x, string[] y)
    {
        return (x, y) switch
        {
            ({ Length: int xLen }, { Length: int yLen })
            when xLen == yLen => x.SequenceEqual(y, StringComparer.OrdinalIgnoreCase),
            _ => false,
        };
    }

    public int GetHashCode(string[] obj)
    {
        return obj is not null ? string.Join(" ", obj).GetHashCode() : default;
    }
}
