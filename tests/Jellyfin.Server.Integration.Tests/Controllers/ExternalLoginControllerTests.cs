using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;
using Jellyfin.Api.Models.UserDtos;
using Jellyfin.Extensions.Json;
using MediaBrowser.Common.Api;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace Jellyfin.Server.Integration.Tests.Controllers
{
    public sealed class ExternalLoginControllerTests : IClassFixture<JellyfinApplicationFactory>
    {
        private const string CodeVerifier = "dBjftJeZ4CVP-mJ92K1qUFSpYpZT6SfTE1WoBN6FGxdN";
        private const string CodeChallenge = "0GpGcQNMruV5OeDMIV9KfGRPUgLOOu6_4IIDATCi454";
        private const string RedirectUri = "/web/#/login";

        private readonly WebApplicationFactory<Startup> _factory;
        private readonly JsonSerializerOptions _jsonOptions = JsonDefaults.Options;

        public ExternalLoginControllerTests(JellyfinApplicationFactory factory)
        {
            _factory = factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
                services.AddAuthentication().AddScheme<AuthenticationSchemeOptions, FakeIdpHandler>("test", "Test IdP", null)));
        }

        private HttpClient CreateClient()
            => _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        private static string StartUrl(string scheme = "test", string redirectUri = RedirectUri, string method = "S256")
            => $"Users/ExternalLogin/{scheme}/Start?redirectUri={Uri.EscapeDataString(redirectUri)}&codeChallenge={CodeChallenge}&codeChallengeMethod={method}&state=abc";

        [Fact]
        public async Task GetAuthenticationMethods_FakeScheme_ListsOnlyRemoteSchemes()
        {
            var client = CreateClient();

            using var response = await client.GetAsync("Users/AuthenticationMethods", TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var methods = await response.Content.ReadFromJsonAsync<AuthenticationMethodDto[]>(_jsonOptions, TestContext.Current.CancellationToken);
            var method = Assert.Single(methods!);
            Assert.Equal("test", method.Id);
            Assert.Equal("Test IdP", method.DisplayName);
        }

        [Fact]
        public async Task ExternalLogin_FullFlow_ExchangesCodeForSession()
        {
            var client = CreateClient();
            await AuthHelper.CompleteStartupAsync(client);

            using var startResponse = await client.GetAsync(StartUrl(), TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Redirect, startResponse.StatusCode);

            using var callbackResponse = await client.GetAsync(startResponse.Headers.Location, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Redirect, callbackResponse.StatusCode);
            Assert.Equal("/Users/ExternalLogin/Complete", callbackResponse.Headers.Location!.OriginalString);

            using var completeResponse = await client.GetAsync(callbackResponse.Headers.Location, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Redirect, completeResponse.StatusCode);
            var location = completeResponse.Headers.Location!.OriginalString;
            Assert.StartsWith("/web/#/login?code=", location, StringComparison.Ordinal);
            Assert.EndsWith("&state=abc", location, StringComparison.Ordinal);
            var code = HttpUtility.ParseQueryString(location[(location.IndexOf('?', StringComparison.Ordinal) + 1)..])["code"];

            var authHeader = AuthHelper.DummyAuthHeader.Replace("69420", "external-login-device", StringComparison.Ordinal);
            using var authRequest = new HttpRequestMessage(HttpMethod.Post, "Users/AuthenticateWithExchangeCode");
            authRequest.Headers.TryAddWithoutValidation(AuthHelper.AuthHeaderName, authHeader);
            authRequest.Content = JsonContent.Create(new ExchangeCodeDto { Code = code!, CodeVerifier = CodeVerifier }, options: _jsonOptions);
            using var authResponse = await client.SendAsync(authRequest, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, authResponse.StatusCode);
            var auth = await authResponse.Content.ReadFromJsonAsync<AuthenticationResult>(_jsonOptions, TestContext.Current.CancellationToken);

            using var meRequest = new HttpRequestMessage(HttpMethod.Get, "Users/Me");
            meRequest.Headers.TryAddWithoutValidation(AuthHelper.AuthHeaderName, authHeader + $", Token={auth!.AccessToken}");
            using var meResponse = await client.SendAsync(meRequest, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, meResponse.StatusCode);

            using var replayResponse = await client.GetAsync("Users/ExternalLogin/Complete", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Unauthorized, replayResponse.StatusCode);
        }

        [Theory]
        [InlineData("test", "https://example.com/callback", "S256", HttpStatusCode.BadRequest)]
        [InlineData("test", "http://localhost:8123/callback", "S256", HttpStatusCode.BadRequest)]
        [InlineData("test", RedirectUri, "plain", HttpStatusCode.BadRequest)]
        [InlineData("unknown", RedirectUri, "S256", HttpStatusCode.NotFound)]
        [InlineData("CustomAuthentication", RedirectUri, "S256", HttpStatusCode.NotFound)]
        public async Task Start_Invalid_ReturnsError(string scheme, string redirectUri, string method, HttpStatusCode expected)
        {
            var client = CreateClient();

            using var response = await client.GetAsync(StartUrl(scheme, redirectUri, method), TestContext.Current.CancellationToken);

            Assert.Equal(expected, response.StatusCode);
        }

        [Fact]
        public async Task Complete_WithoutExternalCookie_ReturnsUnauthorized()
        {
            var client = CreateClient();

            using var response = await client.GetAsync("Users/ExternalLogin/Complete", TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        private sealed class FakeIdpHandler : AuthenticationHandler<AuthenticationSchemeOptions>, IAuthenticationRequestHandler
        {
            private const string CallbackPath = "/test-idp/callback";

            private readonly PropertiesDataFormat _propertiesFormat;

            public FakeIdpHandler(
                IOptionsMonitor<AuthenticationSchemeOptions> options,
                ILoggerFactory logger,
                UrlEncoder encoder,
                IDataProtectionProvider dataProtection)
                : base(options, logger, encoder)
            {
                _propertiesFormat = new PropertiesDataFormat(dataProtection.CreateProtector(nameof(FakeIdpHandler)));
            }

            public async Task<bool> HandleRequestAsync()
            {
                if (!Request.Path.Equals(CallbackPath, StringComparison.Ordinal))
                {
                    return false;
                }

                var properties = _propertiesFormat.Unprotect(Request.Query["state"])!;
                var userId = Context.RequestServices.GetRequiredService<IUserManager>().GetUsersIds().First();
                var principal = new ClaimsPrincipal(new ClaimsIdentity(
                    new[] { new Claim(ExternalAuthentication.UserIdClaimType, userId.ToString()) },
                    "test"));

                await Context.SignInAsync(ExternalAuthentication.SignInScheme, principal, properties);
                Response.Redirect(properties.RedirectUri!);
                return true;
            }

            protected override Task<AuthenticateResult> HandleAuthenticateAsync()
                => Task.FromResult(AuthenticateResult.NoResult());

            protected override Task HandleChallengeAsync(AuthenticationProperties properties)
            {
                Response.Redirect($"{CallbackPath}?state={Uri.EscapeDataString(_propertiesFormat.Protect(properties))}");
                return Task.CompletedTask;
            }
        }
    }
}
