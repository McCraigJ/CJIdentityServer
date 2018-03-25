using System;
using System.Collections.Generic;
using System.Text;

namespace CJ.IdentityServer.ServiceModels.Login
{
  public class LogoutResultSM
  {
    public string PostLogoutRedirectUri { get; set; }
    public string ClientName { get; set; }
    public string ClientId { get; set; }
    public string SignOutIframeUrl { get; set; }        
  }
}
