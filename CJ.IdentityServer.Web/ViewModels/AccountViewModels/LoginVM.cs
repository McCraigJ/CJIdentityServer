﻿using CJ.IdentityServer.Web.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Web.ViewModels.AccountViewModels
{
  public class LoginVM : LoginInputVM
  {
    public bool AllowRememberLogin { get; set; }
    public bool EnableLocalLogin { get; set; }

    public IEnumerable<ExternalProviderPM> ExternalProviders { get; set; }
    public IEnumerable<ExternalProviderPM> VisibleExternalProviders => ExternalProviders.Where(x => !String.IsNullOrWhiteSpace(x.DisplayName));

    public bool IsExternalLoginOnly => EnableLocalLogin == false && ExternalProviders?.Count() == 1;
    public string ExternalLoginScheme => IsExternalLoginOnly ? ExternalProviders?.SingleOrDefault()?.AuthenticationScheme : null;
  }
}
