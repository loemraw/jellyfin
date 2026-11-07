using System;
using System.Threading.Tasks;
using MediaBrowser.Controller.Net;

namespace MediaBrowser.Controller.Authentication;

/// <summary>
/// Manages single-use, short-lived codes that can be redeemed for a session.
/// </summary>
public interface IExchangeCodeManager
{
    /// <summary>
    /// Creates a code for a user, bound to a PKCE S256 code challenge.
    /// </summary>
    /// <param name="userId">The id of the user the code authenticates.</param>
    /// <param name="codeChallenge">The code challenge, <c>BASE64URL(SHA256(ASCII(code_verifier)))</c> without padding.</param>
    /// <returns>The exchange code.</returns>
    /// <exception cref="ArgumentException"><paramref name="userId"/> is empty or <paramref name="codeChallenge"/> is not a valid S256 code challenge.</exception>
    string CreateCode(Guid userId, string codeChallenge);

    /// <summary>
    /// Redeems a code, creating a session for the requesting device.
    /// </summary>
    /// <param name="code">The exchange code.</param>
    /// <param name="codeVerifier">The PKCE code verifier matching the code challenge.</param>
    /// <param name="authorizationInfo">The authorization info of the requesting device.</param>
    /// <param name="remoteEndPoint">The remote end point of the request.</param>
    /// <returns>A <see cref="Task"/> containing the <see cref="AuthenticationResult"/> of the new session.</returns>
    /// <exception cref="AuthenticationException">The code is invalid, expired or already used, or the verifier does not match.</exception>
    /// <exception cref="SecurityException">The user is not allowed to log in.</exception>
    Task<AuthenticationResult> RedeemCodeAsync(string code, string codeVerifier, AuthorizationInfo authorizationInfo, string remoteEndPoint);
}
