using IdentityServer4;
using IdentityServer4.Models;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer
{
  public static class Config
  {
    public static List<Client> GetClients(IConfigurationSection appSettings)
    {
      var clients = new List<Client>
      {
        new Client
        {
            ClientId = "mvc",
            ClientName = "MVC Client",
            AllowedGrantTypes = GrantTypes.Hybrid,
            RequireConsent = true,
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
