using System;
using System.Net;
using System.Text;

namespace Jellyfin.Api.Helpers;

/// <summary>
/// Helper methods for the external login redirect flow.
/// </summary>
public static class ExternalLoginHelper
{
    /// <summary>
    /// Checks whether a client redirect URI is allowed.
    /// Allowed are same-origin relative paths, http loopback IP literals and reverse-DNS private-use schemes (RFC 8252).
    /// </summary>
    /// <param name="redirectUri">The redirect URI.</param>
    /// <returns><c>true</c> if the redirect URI is allowed.</returns>
    public static bool IsAllowedRedirectUri(string? redirectUri)
    {
        if (string.IsNullOrEmpty(redirectUri))
        {
            return false;
        }

        if (redirectUri[0] == '/')
        {
            return (redirectUri.Length == 1 || (redirectUri[1] != '/' && redirectUri[1] != '\\'))
                && !redirectUri.AsSpan().ContainsAnyExceptInRange('!', '~');
        }

        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.Ordinal))
        {
            return IPAddress.TryParse(uri.DnsSafeHost, out var address)
                && (address.Equals(IPAddress.Loopback) || address.Equals(IPAddress.IPv6Loopback));
        }

        return uri.Scheme.Contains('.', StringComparison.Ordinal);
    }

    /// <summary>
    /// Appends the code and state to a redirect URI.
    /// If the URI has a fragment, the parameters are added inside the fragment.
    /// </summary>
    /// <param name="redirectUri">The redirect URI.</param>
    /// <param name="code">The exchange code.</param>
    /// <param name="state">The optional client state.</param>
    /// <returns>The redirect URI including the parameters.</returns>
    public static string AppendCodeAndState(string redirectUri, string code, string? state)
    {
        // Code and state go last, which is inside the fragment if there is one.
        var hasParameters = redirectUri.LastIndexOf('?') > redirectUri.IndexOf('#', StringComparison.Ordinal);
        var builder = new StringBuilder(redirectUri)
            .Append(hasParameters ? '&' : '?')
            .Append("code=").Append(Uri.EscapeDataString(code));

        if (!string.IsNullOrEmpty(state))
        {
            builder.Append("&state=").Append(Uri.EscapeDataString(state));
        }

        return builder.ToString();
    }
}
