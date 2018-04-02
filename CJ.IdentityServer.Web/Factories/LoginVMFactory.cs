using CJ.IdentityServer.Interfaces;
using CJ.IdentityServer.Web.Models;
using CJ.IdentityServer.Web.ViewModels.AccountViewModels;
using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Web.Factories
{
  public static class LoginVMFactory
  {

    public static async Task<LoginVM> BuildLoginVMAsync(ISecurableService securableService, IAuthenticationSchemeProvider schemeProvider, string returnUrl)
    {
      var context = await securableService.GetAuthorizationContextAsync(returnUrl);

      if (context?.IdP != null)
      {
        // this is meant to short circuit the UI and only trigger the one external IdP
        return new LoginVM
        {
          EnableLocalLogin = false,
          ReturnUrl = returnUrl,
          Username = context?.LoginHint,
          ExternalProviders = new ExternalProviderPM[] { new ExternalProviderPM { AuthenticationScheme = context.IdP } }
        };
      }

      var schemes = await schemeProvider.GetAllSchemesAsync();

      var providers = schemes
          .Where(x => x.DisplayName != null ||
                      (x.Name.Equals(AccountOptionsOM.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase))
          )
          .Select(x => new ExternalProviderPM
          {
            DisplayName = x.Name == "Windows" ? x.Name : x.DisplayName,
            AuthenticationScheme = x.Name
          }).ToList();

      var allowLocal = true;
      if (context?.ClientId != null)
      {
        var client = await securableService.FindEnabledClientByIdAsync(context.ClientId);
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
        AllowRememberLogin = AccountOptionsOM.AllowRememberLogin,
        EnableLocalLogin = allowLocal && AccountOptionsOM.AllowLocalLogin,
        ReturnUrl = returnUrl,
        Username = context?.LoginHint,
        ExternalProviders = providers.ToArray()
      };
    }

    public static async Task<LoginVM> BuildLoginVMAsync(ISecurableService securableService, IAuthenticationSchemeProvider schemeProvider, LoginInputVM model)
    {
      var vm = await BuildLoginVMAsync(securableService, schemeProvider, model.ReturnUrl);
      vm.Username = model.Username;
      vm.RememberLogin = model.RememberLogin;
      return vm;
    }

  }
}
