using CJ.IdentityServer.Interfaces;
using CJ.IdentityServer.ServiceModels.Client;
using CJ.IdentityServer.ServiceModels.Identity;
using CJ.IdentityServer.Web.Models;
using CJ.IdentityServer.Web.ViewModels.ConsentViewModels;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Web.Factories
{
  public static class ConsentVMFactory
  {
    public static async Task<ConsentVM> BuildConsentVMAsync(ISecurableService securableService, ILogger logger, string returnUrl, ConsentInputVM model = null)
    {
      AuthorisationRequestSM request = await securableService.GetAuthorizationContextAsync(returnUrl);
      if (request != null)
      {
        var client = await securableService.FindEnabledClientByIdAsync(request.ClientId);
        if (client != null)
        {          
          var resources = await securableService.FindEnabledResourcesByScopeAsync(request.ScopesRequested);
          if (resources != null && (resources.IdentityResources.Any() || resources.ApiResources.Any()))
          {
            return CreateConsentViewModel(securableService, model, returnUrl, request, client, resources);
          }
          else
          {
            logger.LogError("No scopes matching: {0}", request.ScopesRequested.Aggregate((x, y) => x + ", " + y));
          }
        }
        else
        {
          logger.LogError("Invalid client id: {0}", request.ClientId);
        }
      }
      else
      {
        logger.LogError("No consent request matching request: {0}", returnUrl);
      }

      return null;
    }

    private static ConsentVM CreateConsentViewModel(ISecurableService securableService, ConsentInputVM model, string returnUrl, AuthorisationRequestSM request, 
      ClientSM client, SecurableResourcesSM resources)
    {
      var vm = new ConsentVM
      {
        RememberConsent = model?.RememberConsent ?? true,
        ScopesConsented = model?.ScopesConsented ?? Enumerable.Empty<string>(),

        ReturnUrl = returnUrl,

        ClientName = client.ClientName ?? client.ClientId,
        ClientUrl = client.ClientUri,
        ClientLogoUrl = client.LogoUri,
        AllowRememberConsent = client.AllowRememberConsent
      };

      vm.IdentityScopes = resources.IdentityResources.Select(x => CreateScopeViewModel(x, vm.ScopesConsented.Contains(x.Name) || model == null)).ToArray();
      vm.ResourceScopes = resources.ApiResources.SelectMany(x => x.Scopes).Select(x => CreateScopeViewModel(x, vm.ScopesConsented.Contains(x.Name) || model == null)).ToArray();
      if (ConsentOptionsOM.EnableOfflineAccess && resources.OfflineAccess)
      {
        vm.ResourceScopes = vm.ResourceScopes.Union(new ScopeVM[] {
            GetOfflineAccessScope(securableService, vm.ScopesConsented.Contains(IdentityServer4.IdentityServerConstants.StandardScopes.OfflineAccess) || model == null)
        });
      }

      return vm;
    }

    private static ScopeVM CreateScopeViewModel(IdentityResourceSM identity, bool check)
    {
      return new ScopeVM
      {
        Name = identity.Name,
        DisplayName = identity.DisplayName,
        Description = identity.Description,
        Emphasize = identity.Emphasize,
        Required = identity.Required,
        Checked = check || identity.Required
      };
    }

    private static ScopeVM CreateScopeViewModel(ScopeSM scope, bool check)
    {
      return new ScopeVM
      {
        Name = scope.Name,
        DisplayName = scope.DisplayName,
        Description = scope.Description,
        Emphasize = scope.Emphasize,
        Required = scope.Required,
        Checked = check || scope.Required
      };
    }

    private static ScopeVM GetOfflineAccessScope(ISecurableService securableService, bool check)
    {
      return new ScopeVM
      {
        Name = securableService.GetOfflineAccessScopeName(),
        DisplayName = ConsentOptionsOM.OfflineAccessDisplayName,
        Description = ConsentOptionsOM.OfflineAccessDescription,
        Emphasize = true,
        Checked = check
      };
    }
  }
}
