using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CJ.IdentityServer.ControllerHelpers;
using CJ.IdentityServer.ViewModels.ConsentViewModels;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace CJ.IdentityServer.Controllers
{
  public class ConsentController : Controller
  {

    private readonly IIdentityServerInteractionService _interaction;
    private readonly IClientStore _clientStore;
    private readonly IResourceStore _resourceStore;
    private readonly ILogger<ConsentController> _logger;

    private readonly ConsentControllerHelper _consentHelper;

    public ConsentController(
         IIdentityServerInteractionService interaction,
         IClientStore clientStore,
         IResourceStore resourceStore,
         ILogger<ConsentController> logger)
    {
      _interaction = interaction;
      _clientStore = clientStore;
      _resourceStore = resourceStore;
      _logger = logger;

      _consentHelper = new ConsentControllerHelper(_interaction, _clientStore, _resourceStore, _logger);
    }

    /// <summary>
    /// Shows the consent screen
    /// </summary>
    /// <param name="returnUrl"></param>
    /// <returns></returns>
    [HttpGet]
    public async Task<IActionResult> Index(string returnUrl)
    {
      var vm = await _consentHelper.BuildViewModelAsync(returnUrl);
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
      var result = await _consentHelper.ProcessConsent(model);

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

  }
}