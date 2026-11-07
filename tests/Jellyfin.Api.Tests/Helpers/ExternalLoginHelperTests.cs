using Jellyfin.Api.Helpers;
using Xunit;

namespace Jellyfin.Api.Tests.Helpers
{
    public static class ExternalLoginHelperTests
    {
        [Theory]
        [InlineData("/")]
        [InlineData("/web/")]
        [InlineData("/web/#/login")]
        [InlineData("/web/index.html?a=b#/login")]
        [InlineData("http://127.0.0.1/callback")]
        [InlineData("http://127.0.0.1:8123/callback")]
        [InlineData("http://[::1]:8123/callback")]
        [InlineData("org.jellyfin.mobile:/login")]
        [InlineData("org.jellyfin.mobile://login")]
        public static void IsAllowedRedirectUri_Allowed_ReturnsTrue(string redirectUri)
        {
            Assert.True(ExternalLoginHelper.IsAllowedRedirectUri(redirectUri));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("//evil.example/path")]
        [InlineData("/\\evil.example")]
        [InlineData("/\t/evil.example")]
        [InlineData("/ /evil.example")]
        [InlineData("web/login")]
        [InlineData("https://example.com/callback")]
        [InlineData("http://example.com/callback")]
        [InlineData("https://127.0.0.1/callback")]
        [InlineData("http://localhost:8123/callback")]
        [InlineData("http://127.0.0.1@evil.example/callback")]
        [InlineData("http://192.168.1.10/callback")]
        [InlineData("jellyfin://login")]
        [InlineData("javascript:alert(1)")]
        [InlineData("data:text/html,hello")]
        [InlineData("file:///etc/passwd")]
        public static void IsAllowedRedirectUri_Rejected_ReturnsFalse(string? redirectUri)
        {
            Assert.False(ExternalLoginHelper.IsAllowedRedirectUri(redirectUri));
        }

        [Theory]
        [InlineData("/web/", "abc", "xyz", "/web/?code=abc&state=xyz")]
        [InlineData("/web/", "abc", null, "/web/?code=abc")]
        [InlineData("/web/", "abc", "", "/web/?code=abc")]
        [InlineData("/web/?a=b", "abc", "xyz", "/web/?a=b&code=abc&state=xyz")]
        [InlineData("/web/?a=b", "abc", null, "/web/?a=b&code=abc")]
        [InlineData("/web/#/login", "abc", "xyz", "/web/#/login?code=abc&state=xyz")]
        [InlineData("/web/#/login", "abc", null, "/web/#/login?code=abc")]
        [InlineData("/web/#/login?a=b", "abc", "xyz", "/web/#/login?a=b&code=abc&state=xyz")]
        [InlineData("/web/#/login?a=b", "abc", null, "/web/#/login?a=b&code=abc")]
        [InlineData("/web/?a=b#/login", "abc", "xyz", "/web/?a=b#/login?code=abc&state=xyz")]
        [InlineData("/web/?a=b#/login?c=d", "abc", "xyz", "/web/?a=b#/login?c=d&code=abc&state=xyz")]
        [InlineData("org.jellyfin.mobile:/login", "abc", "xyz", "org.jellyfin.mobile:/login?code=abc&state=xyz")]
        [InlineData("http://127.0.0.1:8123/callback", "abc", null, "http://127.0.0.1:8123/callback?code=abc")]
        [InlineData("/web/", "a+b/c=", "x y&z", "/web/?code=a%2Bb%2Fc%3D&state=x%20y%26z")]
        public static void AppendCodeAndState_ReturnsExpected(string redirectUri, string code, string? state, string expected)
        {
            Assert.Equal(expected, ExternalLoginHelper.AppendCodeAndState(redirectUri, code, state));
        }
    }
}
