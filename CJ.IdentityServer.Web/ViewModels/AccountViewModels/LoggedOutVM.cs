using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Web.ViewModels.AccountViewModels
{
  public class LoggedOutVM
  {
    public string PostLogoutRedirectUri { get; set; }
    public string ClientName { get; set; }
    public string SignOutIframeUrl { get; set; }

    public bool AutomaticRedirectAfterSignOut { get; set; }

    public string LogoutId { get; set; }
    public bool TriggerExternalSignout => ExternalAuthenticationScheme != null;
    public string ExternalAuthenticationScheme { get; set; }
  }
}
