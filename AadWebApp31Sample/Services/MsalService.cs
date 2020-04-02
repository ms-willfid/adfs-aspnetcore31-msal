using SampleApp.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SampleApp.Services
{
    public interface IMsalService
    {
        public Task<string> GetTokenUsingAuthorizationCode(string code);
        public Task<string> GetToken(string scope);
    }


    public class MsalService : IMsalService
    {
        private IConfidentialClientApplication client;

        private IConfiguration Configuration { get; }
        private IHttpContextAccessor UserHttpContext { get; }


        string ClientId;
        string Authority;
        string ClientSecret;
        string RedirectUri;

        public MsalService(IConfiguration Configuration, IHttpContextAccessor UserHttpContext)
        {
            this.Configuration = Configuration;
            this.UserHttpContext = UserHttpContext;

            ClientId = Configuration["ADFS:ClientId"];
            Authority = $"{Configuration["ADFS:Instance"]}{Configuration["ADFS:TenantId"]}";
            ClientSecret = Configuration["ADFS:ClientSecret"];

            var CallbackPath = Configuration["ADFS:CallbackPath"];

            RedirectUri = $"{UserHttpContext.HttpContext.Request.Scheme}://{UserHttpContext.HttpContext.Request.Host}{CallbackPath}";

            client = ConfidentialClientApplicationBuilder.Create(ClientId)
                .WithAdfsAuthority(Authority)
                .WithRedirectUri(RedirectUri)
                .WithClientSecret(ClientSecret)
                .Build();
        }

        public async Task<string> GetTokenUsingAuthorizationCode(string code)
        {
            string[] scopes = { Configuration["Api:scopes"] };
            var result = await client.AcquireTokenByAuthorizationCode(scopes, code).ExecuteAsync().ConfigureAwait(false);
            return result.AccessToken;
        }

        public async Task<string> GetToken(string scope)
        {
            var scopes = scope.Split(" ");

            var _claimsPrincipal = UserHttpContext.HttpContext.User;

            var upn = GetUsername(_claimsPrincipal);

            var account = await GetAccountByUsername(upn);

            //var account = await client.GetAccountAsync(upn.Value);
            var result = await client.AcquireTokenSilent(scopes, account).ExecuteAsync().ConfigureAwait(false);
            return result.AccessToken;
        }


        public async Task<IAccount> GetAccountByUsername(string username)
        {
            var accounts = await client.GetAccountsAsync();
            var account = accounts.Where(a => a.Username == username).FirstOrDefault();
            return account;
        }


        public string GetMsalAccountId(ClaimsPrincipal claimsPrincipal)
        {
            string userObjectId = GetObjectId(claimsPrincipal);
            string nameIdentifierId = GetNameIdentifierId(claimsPrincipal);
            string tenantId = GetTenantId(claimsPrincipal);
            string userFlowId = GetUserFlowId(claimsPrincipal);

            if (!string.IsNullOrWhiteSpace(nameIdentifierId) &&
                !string.IsNullOrWhiteSpace(tenantId) &&
                !string.IsNullOrWhiteSpace(userFlowId))
            {
                // B2C pattern: {oid}-{userFlow}.{tid}
                return $"{nameIdentifierId}.{tenantId}";
            }
            else if (!string.IsNullOrWhiteSpace(userObjectId) && !string.IsNullOrWhiteSpace(tenantId))
            {
                // AAD pattern: {oid}.{tid}
                return $"{userObjectId}.{tenantId}";
            }

            return null;
        }


        public string GetUsername(ClaimsPrincipal claimsPrincipal)
        {

            string username = claimsPrincipal.FindFirstValue(CustomClaimTypes.PreferredUserName);
            if (string.IsNullOrEmpty(username))
            {
                var upnClaim = claimsPrincipal.Claims.Where(c => c.Type.Contains("upn")).FirstOrDefault();
                return upnClaim?.Value;
            }
            return username;
        }


        public string GetObjectId( ClaimsPrincipal claimsPrincipal)
        {
            string userObjectId = claimsPrincipal.FindFirstValue(CustomClaimTypes.Oid);
            if (string.IsNullOrEmpty(userObjectId))
            {
                userObjectId = claimsPrincipal.FindFirstValue(CustomClaimTypes.ObjectId);
            }
            return userObjectId;
        }


        public string GetTenantId( ClaimsPrincipal claimsPrincipal)
        {
            string tenantId = claimsPrincipal.FindFirstValue(CustomClaimTypes.Tid);
            if (string.IsNullOrEmpty(tenantId))
            {
                return claimsPrincipal.FindFirstValue(CustomClaimTypes.TenantId);
            }

            return tenantId;
        }


        public static string GetNameIdentifierId(ClaimsPrincipal claimsPrincipal)
        {
            return claimsPrincipal.FindFirstValue(CustomClaimTypes.UniqueObjectIdentifier);
        }


        public static string GetUserFlowId(ClaimsPrincipal claimsPrincipal)
        {
            string userFlowId = claimsPrincipal.FindFirstValue(CustomClaimTypes.Tfp);
            if (string.IsNullOrEmpty(userFlowId))
            {
                return claimsPrincipal.FindFirstValue(CustomClaimTypes.UserFlow);
            }

            return userFlowId;
        }
    }
}
