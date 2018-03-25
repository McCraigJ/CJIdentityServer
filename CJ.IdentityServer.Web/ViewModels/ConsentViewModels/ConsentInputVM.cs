using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Web.ViewModels.ConsentViewModels
{
  public class ConsentInputVM
  {

    public string Button { get; set; }
    public IEnumerable<string> ScopesConsented { get; set; }
    public bool RememberConsent { get; set; }
    public string ReturnUrl { get; set; }

  }
}
