using CJ.IdentityServer.ServiceModels.Client;
using CJ.IdentityServer.ServiceModels.Identity;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Interfaces
{
  public interface ISecurableService
  {
    Task<AuthorisationRequestSM> GetAuthorizationContextAsync(string returnUrl);

    Task<ClientSM> FindEnabledClientByIdAsync(string clientId);

    Task<SecurableResourcesSM> FindEnabledResourcesByScopeAsync(IEnumerable<string> requestedScopes);

    Task<bool> GrantConsentAsync(string returnUrl, ConsentResponseSM grantedConsent);

    string GetOfflineAccessScopeName();

  }
}
