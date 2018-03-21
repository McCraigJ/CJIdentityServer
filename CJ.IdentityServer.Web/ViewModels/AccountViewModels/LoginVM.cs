using CJ.IdentityServer.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.ViewModels.AccountViewModels
{
  public class LoginVM : LoginInputVM
  {
    public bool AllowRememberLogin { get; set; }
    public bool EnableLocalLogin { get; set; }

    public IEnumerable<ExternalProvider> ExternalProviders { get; set; }
    public IEnumerable<ExternalProvider> VisibleExternalProviders => ExternalProviders.Where(x => !String.IsNullOrWhiteSpace(x.DisplayName));

    public bool IsExternalLoginOnly => EnableLocalLogin == false && ExternalProviders?.Count() == 1;
    public string ExternalLoginScheme => IsExternalLoginOnly ? ExternalProviders?.SingleOrDefault()?.AuthenticationScheme : null;
  }
}
