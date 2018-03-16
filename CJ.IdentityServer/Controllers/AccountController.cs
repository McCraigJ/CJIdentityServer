using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using CJ.IdentityServer.ControllerHelpers;
using CJ.IdentityServer.Models;
using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using CJ.IdentityServer.Services;
using CJ.IdentityServer.ViewModels.AccountViewModels;

namespace CJ.IdentityServer.Controllers
{
  public class AccountController : Controller
  {
    private LoginControllerHelper _loginHelper;

    //private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    private readonly IIdentityServerInteractionService _interaction;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IClientStore _clientStore;
    private readonly IEventService _events;

    private readonly IEmailSender _emailSender;
    private readonly ILogger _logger;


    public AccountController(
        //UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager, 
        IIdentityServerInteractionService interaction,
        IAuthenticationSchemeProvider schemeProvider,
        IClientStore clientStore, 
        IEventService events,
        IEmailSender emailSender,
        ILogger<AccountController> logger)
    {
      //_userManager = userManager;
      _signInManager = signInManager;
      _interaction = interaction;
      _schemeProvider = schemeProvider;
      _clientStore = clientStore;
      _events = events;
      
      _loginHelper = new LoginControllerHelper(_interaction, _schemeProvider, _clientStore);
    }

    #region Login

    public async Task<IActionResult> Login(string returnUrl)
    {
      var vm = await _loginHelper.BuildLoginViewModelAsync(returnUrl);

      if (vm.IsExternalLoginOnly)
      {
        // we only have one option for logging in and it's an external provider
        return await ExternalLogin(vm.ExternalLoginScheme, returnUrl);
      }

      return View(vm);
    }

    #endregion

    #region External Login
    /// <summary>
    /// initiate roundtrip to external authentication provider
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> ExternalLogin(string provider, string returnUrl)
    {
      // only support windows login at this stage
      return await ProcessWindowsLoginAsync(returnUrl);
    }

    [HttpGet]
    public async Task<IActionResult> ExternalLoginCallback()
    {
      // read external identity from the temporary cookie
      var result = await HttpContext.AuthenticateAsync(IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme);
      if (result?.Succeeded != true)
      {
        throw new Exception("External authentication error");
      }

      // lookup our user and external provider info
      var (user, provider, providerUserId, claims) = _loginHelper.FindUserInfoFromWindowsAuthProvidor(result);
      //if (user == null)
      //{
      //  // this might be where you might initiate a custom workflow for user registration
      //  // in this sample we don't show how that would be done, as our sample implementation
      //  // simply auto-provisions new external user
      //  user = AutoProvisionUser(provider, providerUserId, claims);
      //}

      // this allows us to collect any additonal claims or properties
      // for the specific prtotocols used and store them in the local auth cookie.
      // this is typically used to store data needed for signout from those protocols.
      var additionalLocalClaims = new List<Claim>();
      var localSignInProps = new AuthenticationProperties();
      _loginHelper.ProcessLoginCallbackForOidc(result, additionalLocalClaims, localSignInProps);      

      // issue authentication cookie for user
      await _events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, user.UserName, user.UserName));
      await HttpContext.SignInAsync(user.UserName, user.UserName, provider, localSignInProps, additionalLocalClaims.ToArray());

      // delete temporary cookie used during external authentication
      await HttpContext.SignOutAsync(IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme);

      // validate return URL and redirect back to authorization endpoint or a local page
      var returnUrl = result.Properties.Items["returnUrl"];
      if (_interaction.IsValidReturnUrl(returnUrl) || Url.IsLocalUrl(returnUrl))
      {
        return Redirect(returnUrl);
      }

      return Redirect("~/");
    }

    private async Task<IActionResult> ProcessWindowsLoginAsync(string returnUrl)
    {
      // see if windows auth has already been requested and succeeded
      var result = await HttpContext.AuthenticateAsync(AccountOptions.WindowsAuthenticationSchemeName);
      if (result?.Principal is WindowsPrincipal wp)
      {
        // we will issue the external cookie and then redirect the
        // user back to the external callback, in essence, tresting windows
        // auth the same as any other external authentication mechanism
        var props = new AuthenticationProperties()
        {
          RedirectUri = Url.Action("ExternalLoginCallback"),
          Items =
                    {
                        { "returnUrl", returnUrl },
                        { "scheme", AccountOptions.WindowsAuthenticationSchemeName },
                    }
        };

        var id = new ClaimsIdentity(AccountOptions.WindowsAuthenticationSchemeName);
        id.AddClaim(new Claim(JwtClaimTypes.Subject, wp.Identity.Name));
        id.AddClaim(new Claim(JwtClaimTypes.Name, wp.Identity.Name));

        // add the groups as claims -- be careful if the number of groups is too large
        if (AccountOptions.IncludeWindowsGroups)
        {
          var wi = wp.Identity as WindowsIdentity;
          var groups = wi.Groups.Translate(typeof(NTAccount));
          var roles = groups.Select(x => new Claim(JwtClaimTypes.Role, x.Value));
          id.AddClaims(roles);
        }

        await HttpContext.SignInAsync(
            IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme,
            new ClaimsPrincipal(id),
            props);
        return Redirect(props.RedirectUri);
      }
      else
      {
        // trigger windows auth
        // since windows auth don't support the redirect uri,
        // this URL is re-triggered when we call challenge
        return Challenge(AccountOptions.WindowsAuthenticationSchemeName);
      }
    }

    #endregion

    #region Logout

    [HttpGet]
    public async Task<IActionResult> Logout(string logoutId)
    {
      await _signInManager.SignOutAsync();
      _logger.LogInformation("User logged out.");

      var logout = await _interaction.GetLogoutContextAsync(logoutId);

      var vm = new LoggedOutVM
      {
        AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
        PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
        ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
        SignOutIframeUrl = logout?.SignOutIFrameUrl,
        LogoutId = logoutId
      };

      return View("LoggedOut", vm);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
      await _signInManager.SignOutAsync();
      _logger.LogInformation("User logged out.");
      return RedirectToAction(nameof(HomeController.Index), "Home");
    }

    #endregion


  }
}