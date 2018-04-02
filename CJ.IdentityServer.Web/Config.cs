using IdentityServer4;
using IdentityServer4.Models;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;

namespace CJ.IdentityServer.Web
{
  public static class Config    
  {

    public const string WindowsUserPassword = "D3309ssda_01-29940";

    public static List<Client> GetClients(IConfigurationSection appSettings)
    {
      var clients = new List<Client>
      {
        new Client
        {
            ClientId = "mvc",
            ClientName = "MVC Client",
            AllowedGrantTypes = GrantTypes.HybridAndClientCredentials,
            RequireConsent = true,
            AlwaysIncludeUserClaimsInIdToken = true,
            ClientSecrets =
            {
              new Secret("secret".Sha256()) 
            },

            // where to redirect to after login
            RedirectUris = { appSettings["SignInReturnUri"] }, // "http://localhost:5002/signin-oidc" },

            // where to redirect to after logout
            PostLogoutRedirectUris = { appSettings["PostSignOutUri"] }, // http://localhost:5002/signout-callback-oidc

            AllowedScopes = new List<string>
            {
              IdentityServerConstants.StandardScopes.OpenId,
              IdentityServerConstants.StandardScopes.Profile
            }
        }
      };
      return clients;

    }

    public static List<IdentityResource> GetIdentityResources()
    {
      return new List<IdentityResource>
      {
          new IdentityResources.OpenId(),
          new IdentityResources.Profile(),
      };
    }


  }
}
