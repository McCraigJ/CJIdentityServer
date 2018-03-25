﻿
using CJ.IdentityServer.Web.ViewModels.ConsentViewModels;
using CJ.IdentityServer.Web.Controllers;
using CJ.IdentityServer.Web.Models;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Threading.Tasks;
using CJ.IdentityServer.Interfaces;
using CJ.IdentityServer.ServiceModels.Identity;
using CJ.IdentityServer.ServiceModels.Client;

namespace CJ.IdentityServer.Web.ControllerHelpers
{
  public class ConsentControllerHelper
  {
    //private readonly IIdentityServerInteractionService _interaction;
    //private readonly IClientStore _clientStore;
    private readonly IResourceStore _resourceStore;
    private readonly ILogger<ConsentController> _logger;
    private readonly ISecurableService _securableService;

    public ConsentControllerHelper(
         //IIdentityServerInteractionService interaction,
         //IClientStore clientStore,
         IResourceStore resourceStore,
         ISecurableService securableService,
         ILogger<ConsentController> logger)
    {
      //_interaction = interaction;
      //_clientStore = clientStore;
      _resourceStore = resourceStore;
      _securableService = securableService;
      _logger = logger;
    }

    public async Task<ConsentVM> BuildViewModelAsync(string returnUrl, ConsentInputVM model = null)
    {
      AuthorisationRequestSM request = await _securableService.GetAuthorizationContextAsync(returnUrl);
      if (request != null)
      {
        var client = await _securableService.FindEnabledClientByIdAsync(request.ClientId);
        if (client != null)
        {
          //var resources = await _resourceStore.FindEnabledResourcesByScopeAsync(request.ScopesRequested);
          var resources = await _securableService.FindEnabledResourcesByScopeAsync(request.ScopesRequested);
          if (resources != null && (resources.IdentityResources.Any() || resources.ApiResources.Any()))
          {
            return CreateConsentViewModel(model, returnUrl, request, client, resources);
          }
          else
          {
            _logger.LogError("No scopes matching: {0}", request.ScopesRequested.Aggregate((x, y) => x + ", " + y));
          }
        }
        else
        {
          _logger.LogError("Invalid client id: {0}", request.ClientId);
        }
      }
      else
      {
        _logger.LogError("No consent request matching request: {0}", returnUrl);
      }

      return null;
    }

    /*****************************************/
    /* helper APIs for the ConsentController */
    /*****************************************/
    public async Task<ProcessConsentResult> ProcessConsent(ConsentInputVM model)
    {
      var result = new ProcessConsentResult();

      ConsentResponse grantedConsent = null;

      // user clicked 'no' - send back the standard 'access_denied' response
      if (model.Button == "no")
      {
        grantedConsent = ConsentResponse.Denied;
      }
      // user clicked 'yes' - validate the data
      else if (model.Button == "yes" && model != null)
      {
        // if the user consented to some scope, build the response model
        if (model.ScopesConsented != null && model.ScopesConsented.Any())
        {
          var scopes = model.ScopesConsented;
          if (ConsentOptions.EnableOfflineAccess == false)
          {
            scopes = scopes.Where(x => x != IdentityServer4.IdentityServerConstants.StandardScopes.OfflineAccess);
          }

          grantedConsent = new ConsentResponse
          {
            RememberConsent = model.RememberConsent,
            ScopesConsented = scopes.ToArray()
          };
        }
        else
        {
          result.ValidationError = ConsentOptions.MustChooseOneErrorMessage;
        }
      }
      else
      {
        result.ValidationError = ConsentOptions.InvalidSelectionErrorMessage;
      }

      if (grantedConsent != null)
      {
        // validate return url is still valid
        var request = await _securableService.GetAuthorizationContextAsync(model.ReturnUrl);
        if (request == null) return result;

        // communicate outcome of consent back to identityserver
        await _securableService.GrantConsentAsync(request, grantedConsent);

        // indicate that's it ok to redirect back to authorization endpoint
        result.RedirectUri = model.ReturnUrl;
      }
      else
      {
        // we need to redisplay the consent UI
        result.ViewModel = await BuildViewModelAsync(model.ReturnUrl, model);
      }

      return result;
    }

    private ConsentVM CreateConsentViewModel(ConsentInputVM model, string returnUrl, AuthorisationRequestSM request, ClientSM client, SecurableResourcesSM resources)
    {
      var vm = new ConsentVM();
      vm.RememberConsent = model?.RememberConsent ?? true;
      vm.ScopesConsented = model?.ScopesConsented ?? Enumerable.Empty<string>();

      vm.ReturnUrl = returnUrl;

      vm.ClientName = client.ClientName ?? client.ClientId;
      vm.ClientUrl = client.ClientUri;
      vm.ClientLogoUrl = client.LogoUri;
      vm.AllowRememberConsent = client.AllowRememberConsent;

      vm.IdentityScopes = resources.IdentityResources.Select(x => CreateScopeViewModel(x, vm.ScopesConsented.Contains(x.Name) || model == null)).ToArray();
      vm.ResourceScopes = resources.ApiResources.SelectMany(x => x.Scopes).Select(x => CreateScopeViewModel(x, vm.ScopesConsented.Contains(x.Name) || model == null)).ToArray();
      if (ConsentOptions.EnableOfflineAccess && resources.OfflineAccess)
      {
        vm.ResourceScopes = vm.ResourceScopes.Union(new ScopeVM[] {
                    GetOfflineAccessScope(vm.ScopesConsented.Contains(IdentityServer4.IdentityServerConstants.StandardScopes.OfflineAccess) || model == null)
                });
      }

      return vm;
    }

    private ScopeVM CreateScopeViewModel(IdentityResource identity, bool check)
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

    private ScopeVM CreateScopeViewModel(Scope scope, bool check)
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

    private ScopeVM GetOfflineAccessScope(bool check)
    {
      return new ScopeVM
      {
        Name = IdentityServer4.IdentityServerConstants.StandardScopes.OfflineAccess,
        DisplayName = ConsentOptions.OfflineAccessDisplayName,
        Description = ConsentOptions.OfflineAccessDescription,
        Emphasize = true,
        Checked = check
      };
    }
  }
}
