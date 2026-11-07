namespace MediaBrowser.Common.Api;

/// <summary>
/// Constants for plugins that provide external (redirect based) authentication.
/// </summary>
public static class ExternalAuthentication
{
    /// <summary>
    /// Authentication scheme plugins must use as the <c>SignInScheme</c> of their remote authentication handler.
    /// </summary>
    public const string SignInScheme = "Jellyfin.External";

    /// <summary>
    /// Claim type carrying the Jellyfin user id, as a <see cref="System.Guid"/> string, on the principal signed into <see cref="SignInScheme"/>.
    /// </summary>
    public const string UserIdClaimType = "Jellyfin-ExternalUserId";
}
