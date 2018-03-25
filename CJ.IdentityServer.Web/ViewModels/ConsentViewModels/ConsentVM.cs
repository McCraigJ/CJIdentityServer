using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Web.ViewModels.ConsentViewModels
{
  public class ConsentVM : ConsentInputVM
  {
    public string ClientName { get; set; }
    public string ClientUrl { get; set; }
    public string ClientLogoUrl { get; set; }
    public bool AllowRememberConsent { get; set; }

    public IEnumerable<ScopeVM> IdentityScopes { get; set; }
    public IEnumerable<ScopeVM> ResourceScopes { get; set; }
  }
}
