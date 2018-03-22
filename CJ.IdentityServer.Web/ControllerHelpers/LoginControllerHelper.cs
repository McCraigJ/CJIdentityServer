using IdentityModel;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using CJ.IdentityServer.ViewModels.AccountViewModels;
using CJ.IdentityServer.Models;
using System.Collections.Generic;

namespace CJ.IdentityServer.ControllerHelpers
{
  public class LoginControllerHelper
  {
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IClientStore _clientStore;

    public LoginControllerHelper(IIdentityServerInteractionService interaction, IAuthenticationSchemeProvider schemeProvider,
      IClientStore clientStore)
    {
      _interaction = interaction;
      _schemeProvider = schemeProvider;
      _clientStore = clientStore;
    }

    public async Task<LoginVM> BuildLoginViewModelAsync(string returnUrl)
    {
      var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
      if (context?.IdP != null)
      {
        // this is meant to short circuit the UI and only trigger the one external IdP
        return new LoginVM
        {
          EnableLocalLogin = false,
          ReturnUrl = returnUrl,
          Username = context?.LoginHint,
          ExternalProviders = new ExternalProvider[] { new ExternalProvider { AuthenticationScheme = context.IdP } }
        };
      }

      var schemes = await _schemeProvider.GetAllSchemesAsync();

      var providers = schemes
          .Where(x => x.DisplayName != null ||
                      (x.Name.Equals(AccountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase))
          )
          .Select(x => new ExternalProvider
          {
            DisplayName = x.Name == "Windows" ? x.Name : x.DisplayName,
            AuthenticationScheme = x.Name
          }).ToList();

      var allowLocal = true;
      if (context?.ClientId != null)
      {
        var client = await _clientStore.FindEnabledClientByIdAsync(context.ClientId);
        if (client != null)
        {
          allowLocal = client.EnableLocalLogin;

          if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
          {
            providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
          }
        }
      }

      return new LoginVM
      {
        AllowRememberLogin = AccountOptions.AllowRememberLogin,
        EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
        ReturnUrl = returnUrl,
        Username = context?.LoginHint,
        ExternalProviders = providers.ToArray()
      };
    }

    public async Task<LoginVM> BuildLoginViewModelAsync(LoginInputVM model)
    {
      var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
      vm.Username = model.Username;
      vm.RememberLogin = model.RememberLogin;
      return vm;
    }

    public (ApplicationUser user, string provider, string providerUserId, IEnumerable<Claim> claims) FindUserInfoFromWindowsAuthProvidor(AuthenticateResult result)
    {
      var externalUser = result.Principal;

      // try to determine the unique id of the external user (issued by the provider)
      // the most common claim type for that are the sub claim and the NameIdentifier
      // depending on the external provider, some other claim type might be used
      var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                        externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                        throw new Exception("Unknown userid");

      // remove the user id claim so we don't include it as an extra claim if/when we provision the user
      var claims = externalUser.Claims.ToList();
      claims.Remove(userIdClaim);

      var provider = result.Properties.Items["scheme"];
      var providerUserId = userIdClaim.Value;

      // find external user
      //var user = //_users.FindByExternalProvider(provider, providerUserId);
      
      var user = new ApplicationUser
      {
        Id = userIdClaim.Value,
        UserName = userIdClaim.Value
      };


      return (user, provider, providerUserId, claims);
    }

    public void ProcessLoginCallbackForOidc(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
    {
      // if the external system sent a session id claim, copy it over
      // so we can use it for single sign-out
      var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
      if (sid != null)
      {
        localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
      }

      // if the external provider issued an id_token, we'll keep it for signout
      var id_token = externalResult.Properties.GetTokenValue("id_token");
      if (id_token != null)
      {
        localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = id_token } });
      }
    }

  }
}
