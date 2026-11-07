using System.ComponentModel.DataAnnotations;

namespace Jellyfin.Api.Models.UserDtos;

/// <summary>
/// The exchange code request body.
/// </summary>
public class ExchangeCodeDto
{
    /// <summary>
    /// Gets or sets the exchange code.
    /// </summary>
    [Required]
    public string Code { get; set; } = null!;

    /// <summary>
    /// Gets or sets the PKCE code verifier.
    /// </summary>
    [Required]
    public string CodeVerifier { get; set; } = null!;
}
