using CJ.IdentityServer.ServiceModels;
using CJ.IdentityServer.ServiceModels.Client;
using CJ.IdentityServer.ServiceModels.Identity;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Interfaces
{
  public interface ISecurableService
  {
    Task<AuthorisationRequestSM> GetAuthorizationContextAsync(string returnUrl);

    Task<ClientSM> FindEnabledClientByIdAsync(string clientId);

    Task<SecurableResourcesSM> FindEnabledResourcesByScopeAsync(IEnumerable<string> requestedScopes);

    Task GrantConsentAsync(AuthorisationRequestSM request, )


  }
}
