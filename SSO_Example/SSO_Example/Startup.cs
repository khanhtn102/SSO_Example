using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Claims;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Newtonsoft.Json;
using Owin;

[assembly: OwinStartup(typeof(SSO_Example.Startup))]

namespace SSO_Example
{
	public class Startup
	{
		private readonly string _clientId = ConfigurationManager.AppSettings["okta:ClientId"];
		private readonly string _redirectUri = ConfigurationManager.AppSettings["okta:RedirectUri"];
		private readonly string _authority = ConfigurationManager.AppSettings["okta:OrgUri"];
		private readonly string _clientSecret = ConfigurationManager.AppSettings["okta:ClientSecret"];

		public void Configuration(IAppBuilder app)
		{
			// For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=316888
			ConfigureAuth(app);
		}

		public void ConfigureAuth(IAppBuilder app)
		{
			app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);
			app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
			app.UseCookieAuthentication(new CookieAuthenticationOptions());

			app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
			{
				ClientId = _clientId,
				ClientSecret = _clientSecret,
				Authority = _authority,
				RedirectUri = _redirectUri,
				ResponseType = OpenIdConnectResponseType.Code,
				Scope = OpenIdConnectScope.OpenIdProfile,

				TokenValidationParameters = new TokenValidationParameters()
				{
					NameClaimType = "name",
					ValidateIssuer = true
				},

				Notifications = new OpenIdConnectAuthenticationNotifications
				{
					AuthorizationCodeReceived = async n =>
					{
						// Exchange code for access and ID tokens
						var token = new object();
						var client = new HttpClient();
						var clientCreds = System.Text.Encoding.UTF8.GetBytes($"{_clientId}:{_clientSecret}");

						client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(clientCreds));
						client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

						var postMessage = new Dictionary<string, string>();
						postMessage.Add("grant_type", "client_credentials");
						postMessage.Add("scope", "customScope");

						var request = new HttpRequestMessage(HttpMethod.Post, _authority + "/v1/token")
						{
							Content = new FormUrlEncodedContent(postMessage)
						};

						var response = await client.SendAsync(request);
						if (response.IsSuccessStatusCode)
						{
							var json = await response.Content.ReadAsStringAsync();
							token = JsonConvert.DeserializeObject<object>(json);
						}
						else
						{
							throw new ApplicationException("Unable to retrieve access token from Okta");
						}

						// get user info
						//var userInfoClient = new UserInfoClient(authority + "/v1/userinfo");
						//var userInfoResponse = await userInfoClient.GetAsync(tokenResponse.AccessToken);

						//var claims = new List<Claim>();
						//claims.Add(new Claim("id_token", "123", string.Empty));
						//claims.Add(new Claim("access_token", "123", string.Empty));

						//if (!string.IsNullOrEmpty(tokenResponse.RefreshToken))
						//{
						//	claims.Add(new Claim("refresh_token", tokenResponse.RefreshToken));
						//}

						//n.AuthenticationTicket.Identity.AddClaims(claims);

						return;
					},

					RedirectToIdentityProvider = n =>
					{
						// If signing out, add the id_token_hint
						if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
						{
							var idTokenClaim = n.OwinContext.Authentication.User.FindFirst("id_token");
							if (idTokenClaim != null)
							{
								n.ProtocolMessage.IdTokenHint = idTokenClaim.Value;
							}
						}

						return Task.CompletedTask;
					},

					AuthenticationFailed = n =>
					{
						// redirect to error page
						return Task.CompletedTask;
					}
				}
			});
		}
	}
}
