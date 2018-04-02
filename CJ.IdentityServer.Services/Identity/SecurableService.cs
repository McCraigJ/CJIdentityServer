using AutoMapper;
using CJ.IdentityServer.Interfaces;
using CJ.IdentityServer.ServiceModels;
using CJ.IdentityServer.ServiceModels.Client;
using CJ.IdentityServer.ServiceModels.Identity;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Services.Identity
{
  public class SecurableService : ISecurableService
  {
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IClientStore _clientStore;
    private readonly IResourceStore _resourceStore;

    public SecurableService(
      IIdentityServerInteractionService interaction,
      IAuthenticationSchemeProvider schemeProvider,
      IClientStore clientStore,
      IResourceStore resourceStore)
    {
      _interaction = interaction;
      _schemeProvider = schemeProvider;
      _clientStore = clientStore;
      _resourceStore = resourceStore;
    }

    public async Task<SecurableResourcesSM> FindEnabledResourcesByScopeAsync(IEnumerable<string> requestedScopes)
    {
      var resources = await _resourceStore.FindEnabledResourcesByScopeAsync(requestedScopes);
      return AutoMapper.Mapper.Map<SecurableResourcesSM>(resources);
    }

    public async Task<AuthorisationRequestSM> GetAuthorizationContextAsync(string returnUrl)
    {
      var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
      return AutoMapper.Mapper.Map<AuthorisationRequestSM>(context);
    }

    public async Task<ClientSM> FindEnabledClientByIdAsync(string clientId)
    {
      var client = await _clientStore.FindEnabledClientByIdAsync(clientId);
      return AutoMapper.Mapper.Map<ClientSM>(client);
    }

    public async Task<bool> GrantConsentAsync(string returnUrl, ConsentResponseSM grantedConsent)
    {
      var request = await _interaction.GetAuthorizationContextAsync(returnUrl);
      if (request == null)
      {
        return false;
      }
      else
      {
        await _interaction.GrantConsentAsync(Mapper.Map<AuthorizationRequest>(request), Mapper.Map<ConsentResponse>(grantedConsent));
        return true;
      }
      
    }

    public string GetOfflineAccessScopeName()
    {
      return IdentityServerConstants.StandardScopes.OfflineAccess;
    }
  }
}
