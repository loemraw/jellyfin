using System;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Server.Implementations.Users;
using MediaBrowser.Common.Net;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.Session;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Jellyfin.Server.Implementations.Tests.Users;

public class ExchangeCodeManagerTests
{
    private const string CodeVerifier = "dBjftJeZ4CVP-mJ92K1qUFSpYpZT6SfTE1WoBN6FGxdN";
    private const string CodeChallenge = "0GpGcQNMruV5OeDMIV9KfGRPUgLOOu6_4IIDATCi454";
    private const string RemoteEndPoint = "192.168.1.10";

    private static readonly AuthorizationInfo _authInfo = new AuthorizationInfo
    {
        Device = "Device",
        DeviceId = "DeviceId",
        Client = "Client",
        Version = "1.0.0"
    };

    private readonly Mock<IUserManager> _userManager = new();
    private readonly Mock<ISessionManager> _sessionManager = new();
    private readonly Mock<INetworkManager> _networkManager = new();
    private readonly TestTimeProvider _timeProvider = new();
    private readonly User _user;
    private readonly ExchangeCodeManager _exchangeCodeManager;

    public ExchangeCodeManagerTests()
    {
        _user = new User("user", "auth-provider", "reset-provider") { Id = Guid.NewGuid() };
        _user.AddDefaultPermissions();

        _userManager.Setup(x => x.GetUserById(_user.Id)).Returns(_user);
        _networkManager.Setup(x => x.IsInLocalNetwork(RemoteEndPoint)).Returns(true);
        _sessionManager.Setup(x => x.AuthenticateDirect(It.IsAny<AuthenticationRequest>()))
            .ReturnsAsync(new AuthenticationResult());

        _exchangeCodeManager = new ExchangeCodeManager(
            _userManager.Object,
            _sessionManager.Object,
            _networkManager.Object,
            _timeProvider,
            NullLogger<ExchangeCodeManager>.Instance);
    }

    [Fact]
    public async Task RedeemCodeAsync_ValidCode_AuthenticatesDirect()
    {
        var code = _exchangeCodeManager.CreateCode(_user.Id, CodeChallenge);

        var result = await _exchangeCodeManager.RedeemCodeAsync(code, CodeVerifier, _authInfo, RemoteEndPoint);

        Assert.NotNull(result);
        _sessionManager.Verify(
            x => x.AuthenticateDirect(It.Is<AuthenticationRequest>(r =>
                r.UserId.Equals(_user.Id)
                && r.Username == _user.Username
                && r.App == _authInfo.Client
                && r.AppVersion == _authInfo.Version
                && r.DeviceId == _authInfo.DeviceId
                && r.DeviceName == _authInfo.Device
                && r.RemoteEndPoint == RemoteEndPoint)),
            Times.Once);
    }

    [Fact]
    public async Task RedeemCodeAsync_SecondRedeem_Throws()
    {
        var code = _exchangeCodeManager.CreateCode(_user.Id, CodeChallenge);
        await _exchangeCodeManager.RedeemCodeAsync(code, CodeVerifier, _authInfo, RemoteEndPoint);

        await Assert.ThrowsAsync<AuthenticationException>(
            () => _exchangeCodeManager.RedeemCodeAsync(code, CodeVerifier, _authInfo, RemoteEndPoint));
    }

    [Fact]
    public async Task RedeemCodeAsync_WrongVerifier_ThrowsAndConsumesCode()
    {
        var code = _exchangeCodeManager.CreateCode(_user.Id, CodeChallenge);
        var wrongVerifier = new string('a', 43);

        await Assert.ThrowsAsync<AuthenticationException>(
            () => _exchangeCodeManager.RedeemCodeAsync(code, wrongVerifier, _authInfo, RemoteEndPoint));
        await Assert.ThrowsAsync<AuthenticationException>(
            () => _exchangeCodeManager.RedeemCodeAsync(code, CodeVerifier, _authInfo, RemoteEndPoint));
        _sessionManager.Verify(x => x.AuthenticateDirect(It.IsAny<AuthenticationRequest>()), Times.Never);
    }

    [Theory]
    [InlineData("short")]
    [InlineData("dBjftJeZ4CVP-mJ92K1qUFSpYpZT6SfTE1WoBN6FGxd=")]
    public async Task RedeemCodeAsync_MalformedVerifier_Throws(string verifier)
    {
        var code = _exchangeCodeManager.CreateCode(_user.Id, CodeChallenge);

        await Assert.ThrowsAsync<AuthenticationException>(
            () => _exchangeCodeManager.RedeemCodeAsync(code, verifier, _authInfo, RemoteEndPoint));
    }

    [Fact]
    public async Task RedeemCodeAsync_ExpiredCode_Throws()
    {
        var code = _exchangeCodeManager.CreateCode(_user.Id, CodeChallenge);
        _timeProvider.Advance(TimeSpan.FromSeconds(61));

        await Assert.ThrowsAsync<AuthenticationException>(
            () => _exchangeCodeManager.RedeemCodeAsync(code, CodeVerifier, _authInfo, RemoteEndPoint));
    }

    [Fact]
    public async Task RedeemCodeAsync_UnknownCode_Throws()
    {
        await Assert.ThrowsAsync<AuthenticationException>(
            () => _exchangeCodeManager.RedeemCodeAsync("unknown", CodeVerifier, _authInfo, RemoteEndPoint));
    }

    [Theory]
    [InlineData("")]
    [InlineData("tooshort")]
    [InlineData("0GpGcQNMruV5OeDMIV9KfGRPUgLOOu6_4IIDATCi45=")]
    [InlineData("0GpGcQNMruV5OeDMIV9KfGRPUgLOOu6/4IIDATCi454")]
    public void CreateCode_InvalidChallenge_Throws(string challenge)
    {
        Assert.Throws<ArgumentException>(() => _exchangeCodeManager.CreateCode(_user.Id, challenge));
    }

    [Fact]
    public void CreateCode_EmptyUserId_Throws()
    {
        Assert.Throws<ArgumentException>(() => _exchangeCodeManager.CreateCode(Guid.Empty, CodeChallenge));
    }

    [Fact]
    public async Task RedeemCodeAsync_DisabledUser_ThrowsSecurityException()
    {
        _user.SetPermission(PermissionKind.IsDisabled, true);
        var code = _exchangeCodeManager.CreateCode(_user.Id, CodeChallenge);

        await Assert.ThrowsAsync<SecurityException>(
            () => _exchangeCodeManager.RedeemCodeAsync(code, CodeVerifier, _authInfo, RemoteEndPoint));
    }

    [Fact]
    public async Task RedeemCodeAsync_RemoteAccessDisabledOutsideLocalNetwork_ThrowsSecurityException()
    {
        _user.SetPermission(PermissionKind.EnableRemoteAccess, false);
        _networkManager.Setup(x => x.IsInLocalNetwork("203.0.113.5")).Returns(false);
        var code = _exchangeCodeManager.CreateCode(_user.Id, CodeChallenge);

        await Assert.ThrowsAsync<SecurityException>(
            () => _exchangeCodeManager.RedeemCodeAsync(code, CodeVerifier, _authInfo, "203.0.113.5"));
    }

    [Fact]
    public async Task RedeemCodeAsync_UnknownUser_ThrowsAuthenticationException()
    {
        var code = _exchangeCodeManager.CreateCode(Guid.NewGuid(), CodeChallenge);

        await Assert.ThrowsAsync<AuthenticationException>(
            () => _exchangeCodeManager.RedeemCodeAsync(code, CodeVerifier, _authInfo, RemoteEndPoint));
    }

    private sealed class TestTimeProvider : TimeProvider
    {
        private DateTimeOffset _utcNow = DateTimeOffset.UnixEpoch;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan duration) => _utcNow += duration;
    }
}
