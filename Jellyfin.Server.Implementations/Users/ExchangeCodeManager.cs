using System;
using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Extensions;
using MediaBrowser.Common.Net;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.Session;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Server.Implementations.Users;

/// <summary>
/// Exchange code manager.
/// </summary>
public class ExchangeCodeManager : IExchangeCodeManager
{
    private const int CodeLifetimeSeconds = 60;
    private const int CodeChallengeLength = 43;
    private const int MinCodeVerifierLength = 43;
    private const int MaxCodeVerifierLength = 128;

    private readonly ConcurrentDictionary<string, (Guid UserId, byte[] CodeChallenge, DateTimeOffset Expiry)> _codes = new();

    private readonly IUserManager _userManager;
    private readonly ISessionManager _sessionManager;
    private readonly INetworkManager _networkManager;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<ExchangeCodeManager> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="ExchangeCodeManager"/> class.
    /// </summary>
    /// <param name="userManager">The user manager.</param>
    /// <param name="sessionManager">The session manager.</param>
    /// <param name="networkManager">The network manager.</param>
    /// <param name="timeProvider">The time provider.</param>
    /// <param name="logger">The logger.</param>
    public ExchangeCodeManager(
        IUserManager userManager,
        ISessionManager sessionManager,
        INetworkManager networkManager,
        TimeProvider timeProvider,
        ILogger<ExchangeCodeManager> logger)
    {
        _userManager = userManager;
        _sessionManager = sessionManager;
        _networkManager = networkManager;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    /// <inheritdoc />
    public string CreateCode(Guid userId, string codeChallenge)
    {
        if (userId.IsEmpty())
        {
            throw new ArgumentException("User id must not be empty.", nameof(userId));
        }

        var challenge = new byte[SHA256.HashSizeInBytes];
        if (codeChallenge.Length != CodeChallengeLength
            || !codeChallenge.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_')
            || !Base64Url.TryDecodeFromChars(codeChallenge, challenge, out _))
        {
            throw new ArgumentException("Code challenge must be 43 base64url characters.", nameof(codeChallenge));
        }

        PurgeExpiredCodes();

        var code = RandomNumberGenerator.GetHexString(64, lowercase: true);
        _codes[code] = (userId, challenge, _timeProvider.GetUtcNow().AddSeconds(CodeLifetimeSeconds));
        return code;
    }

    /// <inheritdoc />
    public async Task<AuthenticationResult> RedeemCodeAsync(string code, string codeVerifier, AuthorizationInfo authorizationInfo, string remoteEndPoint)
    {
        PurgeExpiredCodes();

        if (!_codes.TryRemove(code, out var entry)
            || entry.Expiry <= _timeProvider.GetUtcNow()
            || !IsValidCodeVerifier(codeVerifier)
            || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)), entry.CodeChallenge))
        {
            _logger.LogInformation("Exchange code redemption has been denied (IP: {IP}).", remoteEndPoint);
            throw new AuthenticationException("Invalid or expired exchange code.");
        }

        var user = _userManager.GetUserById(entry.UserId);
        if (user is null)
        {
            _logger.LogInformation("Exchange code redemption for unknown user {UserId} has been denied (IP: {IP}).", entry.UserId, remoteEndPoint);
            throw new AuthenticationException("Invalid or expired exchange code.");
        }

        if (user.HasPermission(PermissionKind.IsDisabled))
        {
            _logger.LogInformation(
                "Exchange code redemption for {UserName} has been denied because this account is currently disabled (IP: {IP}).",
                user.Username,
                remoteEndPoint);
            throw new SecurityException(
                $"The {user.Username} account is currently disabled. Please consult with your administrator.");
        }

        if (!user.HasPermission(PermissionKind.EnableRemoteAccess)
            && !_networkManager.IsInLocalNetwork(remoteEndPoint))
        {
            _logger.LogInformation(
                "Exchange code redemption for {UserName} forbidden: remote access disabled and user not in local network (IP: {IP}).",
                user.Username,
                remoteEndPoint);
            throw new SecurityException("Forbidden.");
        }

        if (!user.IsParentalScheduleAllowed())
        {
            _logger.LogInformation(
                "Exchange code redemption for {UserName} is not allowed at this time due parental restrictions (IP: {IP}).",
                user.Username,
                remoteEndPoint);
            throw new SecurityException("User is not allowed access at this time.");
        }

        return await _sessionManager.AuthenticateDirect(new AuthenticationRequest
        {
            UserId = user.Id,
            Username = user.Username,
            App = authorizationInfo.Client,
            AppVersion = authorizationInfo.Version,
            DeviceId = authorizationInfo.DeviceId,
            DeviceName = authorizationInfo.Device,
            RemoteEndPoint = remoteEndPoint
        }).ConfigureAwait(false);
    }

    private static bool IsValidCodeVerifier(string codeVerifier)
        => codeVerifier.Length is >= MinCodeVerifierLength and <= MaxCodeVerifierLength
            && codeVerifier.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~');

    private void PurgeExpiredCodes()
    {
        var now = _timeProvider.GetUtcNow();
        foreach (var (code, entry) in _codes)
        {
            if (entry.Expiry <= now)
            {
                _codes.TryRemove(code, out _);
            }
        }
    }
}
