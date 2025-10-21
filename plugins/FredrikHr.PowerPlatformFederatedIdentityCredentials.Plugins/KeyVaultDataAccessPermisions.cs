namespace FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

[Flags]
internal enum KeyVaultDataAccessPermisions : int
{
    None = 0,
    GetSecret = 1,
    ReadCertificateProperties = 2,
    SignWithKey = 4,
}