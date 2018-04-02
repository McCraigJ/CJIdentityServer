using CJ.IdentityServer.Web.ViewModels.ConsentViewModels;

namespace CJ.IdentityServer.Web.Models
{
  public class ProcessConsentResultPM
  {
    public bool IsRedirect => RedirectUri != null;
    public string RedirectUri { get; set; }

    public bool ShowView => ViewModel != null;
    public ConsentVM ViewModel { get; set; }

    public bool HasValidationError => ValidationError != null;
    public string ValidationError { get; set; }
  }
}
