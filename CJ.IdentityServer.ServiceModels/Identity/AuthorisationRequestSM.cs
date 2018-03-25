using System;
using System.Collections.Generic;
using System.Text;

namespace CJ.IdentityServer.ServiceModels.Identity
{
  public class AuthorisationRequestSM
  {
    public string IdP { get; set; }
    public string ClientId { get; set; }
    public string LoginHint { get; set; }
    public IEnumerable<string> ScopesRequested { get; set; }
  }
}
