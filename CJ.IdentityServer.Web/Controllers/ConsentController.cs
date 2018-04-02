using CJ.IdentityServer.Interfaces;
using CJ.IdentityServer.ServiceModels.Identity;
using CJ.IdentityServer.Web.Models;
using CJ.IdentityServer.Web.Factories;
using CJ.IdentityServer.Web.ViewModels.ConsentViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Web.Controllers
{
  public class ConsentController : ControllerBase
  {    
    private readonly ISecurableService _securableService;
    private readonly ILogger<ConsentController> _logger;    

    public ConsentController(
         ISecurableService securableService,         
         ILogger<ConsentController> logger)
    {      
      _securableService = securableService;
      _logger = logger;      
    }

    /// <summary>
    /// Shows the consent screen
    /// </summary>
    /// <param name="returnUrl"></param>
    /// <returns></returns>
    [HttpGet]
    public async Task<IActionResult> Index(string returnUrl)
    {
      var vm = await ConsentVMFactory.BuildConsentVMAsync(_securableService, _logger, returnUrl);
      if (vm != null)
      {
        return View("Index", vm);
      }

      return View("Error");
    }

    /// <summary>
    /// Handles the consent screen postback
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Index(ConsentInputVM model)
    {
      var result = await ProcessConsentAsync(model);

      if (result.IsRedirect)
      {
        return Redirect(result.RedirectUri);
      }

      if (result.HasValidationError)
      {
        ModelState.AddModelError("", result.ValidationError);
      }

      if (result.ShowView)
      {
        return View("Index", result.ViewModel);
      }

      return View("Error");
    }

    private async Task<ProcessConsentResultPM> ProcessConsentAsync(ConsentInputVM model)
    {
      var result = new ProcessConsentResultPM();

      ConsentResponseSM grantedConsent = null;

      // user clicked 'no' - send back the standard 'access_denied' response
      if (model.Button == "no")
      {
        grantedConsent = ConsentResponseSM.Denied;
      }
      // user clicked 'yes' - validate the data
      else if (model.Button == "yes" && model != null)
      {
        // if the user consented to some scope, build the response model
        if (model.ScopesConsented != null && model.ScopesConsented.Any())
        {
          var scopes = model.ScopesConsented;
          if (ConsentOptionsOM.EnableOfflineAccess == false)
          {
            scopes = scopes.Where(x => x != _securableService.GetOfflineAccessScopeName()); // IdentityServer4.IdentityServerConstants.StandardScopes.OfflineAccess);
          }

          grantedConsent = new ConsentResponseSM
          {
            RememberConsent = model.RememberConsent,
            ScopesConsented = scopes.ToArray()
          };
        }
        else
        {
          result.ValidationError = ConsentOptionsOM.MustChooseOneErrorMessage;
        }
      }
      else
      {
        result.ValidationError = ConsentOptionsOM.InvalidSelectionErrorMessage;
      }

      if (grantedConsent != null)
      {
        // communicate outcome of consent back to identityserver        
        var granted = await _securableService.GrantConsentAsync(model.ReturnUrl, grantedConsent);

        if (!granted)
        {
          return result;
        }

        // indicate that's it ok to redirect back to authorization endpoint
        result.RedirectUri = model.ReturnUrl;
      }
      else
      {
        // we need to redisplay the consent UI
        result.ViewModel = await ConsentVMFactory.BuildConsentVMAsync(_securableService, _logger, model.ReturnUrl, model);
      }

      return result;
    }

  }
}