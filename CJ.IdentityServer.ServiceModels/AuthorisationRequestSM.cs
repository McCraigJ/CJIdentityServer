using System;
using System.Collections.Generic;
using System.Text;

namespace CJ.IdentityServer.ServiceModels
{
  public class AuthorisationRequestSM
  {
    public string IdP { get; set; }
    public string ClientId { get; set; }
    public string LoginHint { get; set; }
  }
}
