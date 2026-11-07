using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Jellyfin.Api.Helpers;
using Jellyfin.Api.Models.UserDtos;
using Jellyfin.Extensions;
using MediaBrowser.Common.Api;
using MediaBrowser.Controller.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Api.Controllers;

/// <summary>
/// External login controller.
/// </summary>
[Route("Users")]
[Tags("Authentication")]
public partial class ExternalLoginController : BaseJellyfinApiController
{
    private const string RedirectUriItem = "Jellyfin.RedirectUri";
    private const string CodeChallengeItem = "Jellyfin.CodeChallenge";
    private const string StateItem = "Jellyfin.State";
    private const int MaxStateLength = 512;

    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IExchangeCodeManager _exchangeCodeManager;

    /// <summary>
    /// Initializes a new instance of the <see cref="ExternalLoginController"/> class.
    /// </summary>
    /// <param name="schemeProvider">Instance of the <see cref="IAuthenticationSchemeProvider"/> interface.</param>
    /// <param name="exchangeCodeManager">Instance of the <see cref="IExchangeCodeManager"/> interface.</param>
    public ExternalLoginController(IAuthenticationSchemeProvider schemeProvider, IExchangeCodeManager exchangeCodeManager)
    {
        _schemeProvider = schemeProvider;
        _exchangeCodeManager = exchangeCodeManager;
    }

    /// <summary>
    /// Gets the available external authentication methods.
    /// </summary>
    /// <response code="200">Authentication methods returned.</response>
    /// <returns>An <see cref="IEnumerable{AuthenticationMethodDto}"/> containing the authentication methods.</returns>
    [HttpGet("AuthenticationMethods")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult<IEnumerable<AuthenticationMethodDto>>> GetAuthenticationMethods()
    {
        var schemes = await _schemeProvider.GetRequestHandlerSchemesAsync().ConfigureAwait(false);
        return Ok(schemes.Select(s => new AuthenticationMethodDto { Id = s.Name, DisplayName = s.DisplayName ?? s.Name }));
    }

    /// <summary>
    /// Starts an external login. The client must open this URL in a browser.
    /// </summary>
    /// <param name="scheme">The authentication scheme name.</param>
    /// <param name="redirectUri">The URI the browser is redirected to with the exchange code.</param>
    /// <param name="codeChallenge">The PKCE code challenge.</param>
    /// <param name="codeChallengeMethod">The PKCE code challenge method. Must be S256.</param>
    /// <param name="state">Optional opaque client state, returned unchanged.</param>
    /// <response code="302">Redirecting to the external identity provider.</response>
    /// <response code="400">Invalid redirect URI, code challenge or state.</response>
    /// <response code="404">Authentication scheme not found.</response>
    /// <returns>A <see cref="ChallengeResult"/>.</returns>
    [HttpGet("ExternalLogin/{scheme}/Start")]
    [ProducesResponseType(StatusCodes.Status302Found)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult> StartExternalLogin(
        [FromRoute, Required] string scheme,
        [FromQuery, Required] string redirectUri,
        [FromQuery, Required] string codeChallenge,
        [FromQuery, Required] string codeChallengeMethod,
        [FromQuery] string? state)
    {
        var schemes = await _schemeProvider.GetRequestHandlerSchemesAsync().ConfigureAwait(false);
        if (!schemes.Any(s => string.Equals(s.Name, scheme, StringComparison.Ordinal)))
        {
            return NotFound();
        }

        if (!string.Equals(codeChallengeMethod, "S256", StringComparison.Ordinal)
            || !CodeChallengeRegex().IsMatch(codeChallenge)
            || !ExternalLoginHelper.IsAllowedRedirectUri(redirectUri)
            || state?.Length > MaxStateLength)
        {
            return BadRequest();
        }

        var properties = new AuthenticationProperties
        {
            RedirectUri = Url.Action(nameof(CompleteExternalLogin)),
            Items =
            {
                [RedirectUriItem] = redirectUri,
                [CodeChallengeItem] = codeChallenge
            }
        };

        if (!string.IsNullOrEmpty(state))
        {
            properties.Items[StateItem] = state;
        }

        return Challenge(properties, scheme);
    }

    /// <summary>
    /// Completes an external login after the identity provider round trip.
    /// </summary>
    /// <response code="302">Redirecting to the client with the exchange code.</response>
    /// <response code="401">No valid external login in progress.</response>
    /// <returns>A <see cref="RedirectResult"/> to the client redirect URI.</returns>
    [HttpGet("ExternalLogin/Complete")]
    [ProducesResponseType(StatusCodes.Status302Found)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult> CompleteExternalLogin()
    {
        var result = await HttpContext.AuthenticateAsync(ExternalAuthentication.SignInScheme).ConfigureAwait(false);
        if (!result.Succeeded
            || !Guid.TryParse(result.Principal.FindFirst(ExternalAuthentication.UserIdClaimType)?.Value, out var userId)
            || userId.IsEmpty())
        {
            return Unauthorized();
        }

        var items = result.Properties.Items;
        if (!items.TryGetValue(RedirectUriItem, out var redirectUri)
            || !items.TryGetValue(CodeChallengeItem, out var codeChallenge)
            || redirectUri is null
            || codeChallenge is null
            || !ExternalLoginHelper.IsAllowedRedirectUri(redirectUri))
        {
            return Unauthorized();
        }

        items.TryGetValue(StateItem, out var state);
        await HttpContext.SignOutAsync(ExternalAuthentication.SignInScheme).ConfigureAwait(false);

        var code = _exchangeCodeManager.CreateCode(userId, codeChallenge);
        return Redirect(ExternalLoginHelper.AppendCodeAndState(redirectUri, code, state));
    }

    [GeneratedRegex("^[A-Za-z0-9_-]{43}$")]
    private static partial Regex CodeChallengeRegex();
}
