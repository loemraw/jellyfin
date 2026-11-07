namespace Jellyfin.Api.Models.UserDtos;

/// <summary>
/// An external authentication method.
/// </summary>
public class AuthenticationMethodDto
{
    /// <summary>
    /// Gets or sets the authentication scheme name.
    /// </summary>
    public required string Id { get; set; }

    /// <summary>
    /// Gets or sets the display name.
    /// </summary>
    public required string DisplayName { get; set; }
}
