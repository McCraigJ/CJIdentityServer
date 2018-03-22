using CJ.IdentityServer.ViewModels.ConsentViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Models
{
  public class ProcessConsentResult
  {
    public bool IsRedirect => RedirectUri != null;
    public string RedirectUri { get; set; }

    public bool ShowView => ViewModel != null;
    public ConsentVM ViewModel { get; set; }

    public bool HasValidationError => ValidationError != null;
    public string ValidationError { get; set; }
  }
}
