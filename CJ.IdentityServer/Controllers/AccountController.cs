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
using IdentityServer4.Models;
using Microsoft.AspNetCore.Authorization;
using CJ.IdentityServer.Extensions;

namespace CJ.IdentityServer.Controllers
{
  public class AccountController : Controller
  {
    private LoginControllerHelper _loginHelper;

    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    private readonly IIdentityServerInteractionService _interaction;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IClientStore _clientStore;
    private readonly IEventService _events;

    private readonly IEmailSender _emailSender;
    private readonly ILogger _logger;


    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager, 
        IIdentityServerInteractionService interaction,
        IAuthenticationSchemeProvider schemeProvider,
        IClientStore clientStore, 
        IEventService events,
        IEmailSender emailSender,
        ILogger<AccountController> logger)
    {
      _userManager = userManager;
      _signInManager = signInManager;
      _interaction = interaction;
      _schemeProvider = schemeProvider;
      _clientStore = clientStore;
      _events = events;
      _emailSender = emailSender;
      _logger = logger;
      
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

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginInputVM model, string button)
    {
      if (button != "login")
      {
        // the user clicked the "cancel" button
        var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);
        if (context != null)
        {
          // if the user cancels, send a result back into IdentityServer as if they 
          // denied the consent (even if this client does not require consent).
          // this will send back an access denied OIDC error response to the client.
          await _interaction.GrantConsentAsync(context, ConsentResponse.Denied);

          // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
          return Redirect(model.ReturnUrl);
        }
        else
        {
          // since we don't have a valid context, then we just go back to the home page
          return Redirect("~/");
        }
      }

      if (ModelState.IsValid)
      {
        // validate username/password against in-memory store
        var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberLogin, lockoutOnFailure: false);
        if (result.Succeeded)
        {

          //var user = await _userManager.GetUserAsync(User);
          var user = await _signInManager.UserManager.FindByNameAsync(model.Username);
          await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName));

          // only set explicit expiration here if user chooses "remember me". 
          // otherwise we rely upon expiration configured in cookie middleware.
          AuthenticationProperties props = null;
          if (AccountOptions.AllowRememberLogin && model.RememberLogin)
          {
            props = new AuthenticationProperties
            {
              IsPersistent = true,
              ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
            };
          };

          // issue authentication cookie with subject ID and username
          await HttpContext.SignInAsync(user.Id, user.UserName, props);

          // make sure the returnUrl is still valid, and if so redirect back to authorize endpoint or a local page
          // the IsLocalUrl check is only necessary if you want to support additional local pages, otherwise IsValidReturnUrl is more strict
          if (_interaction.IsValidReturnUrl(model.ReturnUrl) || Url.IsLocalUrl(model.ReturnUrl))
          {
            return Redirect(model.ReturnUrl);
          }

          return Redirect("~/");
        }

        await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials"));

        ModelState.AddModelError("", AccountOptions.InvalidCredentialsErrorMessage);
      }

      // something went wrong, show form with error
      var vm = await _loginHelper.BuildLoginViewModelAsync(model);
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
      //_logger.LogInformation("User logged out.");

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
      //_logger.LogInformation("User logged out.");
      return RedirectToAction(nameof(HomeController.Index), "Home");
    }

    #endregion


    #region Register

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Register(string returnUrl = null)
    {
      ViewData["ReturnUrl"] = returnUrl;
      var vm = new RegisterVM();
      return View(vm);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterVM model, string returnUrl = null)
    {
      ViewData["ReturnUrl"] = returnUrl;
      if (ModelState.IsValid)
      {
        var user = new ApplicationUser { UserName = model.Email, Email = model.Email, PhoneNumber = model.PhoneNumber };
        var result = await _userManager.CreateAsync(user, model.Password);
        if (result.Succeeded)
        {
          _logger.LogInformation("User created a new account with password.");

          var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
          var callbackUrl = Url.EmailConfirmationLink(user.Id, code, Request.Scheme);
          await _emailSender.SendEmailConfirmationAsync(model.Email, callbackUrl);

          await _signInManager.SignInAsync(user, isPersistent: false);
          _logger.LogInformation("User created a new account with password.");
          return RedirectToLocal(returnUrl);
        }
        AddErrors(result);
      }

      // If we got this far, something failed, redisplay form
      return View(model);
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmEmail(string userId, string code)
    {
      if (userId == null || code == null)
      {
        return RedirectToAction(nameof(HomeController.Index), "Home");
      }
      var user = await _userManager.FindByIdAsync(userId);
      if (user == null)
      {
        throw new ApplicationException($"Unable to load user with ID '{userId}'.");
      }
      var result = await _userManager.ConfirmEmailAsync(user, code);
      return View(result.Succeeded ? "ConfirmEmail" : "Error");
    }

    #endregion

    #region Forgot and Reset Password

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPassword()
    {
      return View();
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordVM model)
    {
      if (ModelState.IsValid)
      {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
        {
          // Don't reveal that the user does not exist or is not confirmed
          return RedirectToAction(nameof(ForgotPasswordConfirmation));
        }

        // For more information on how to enable account confirmation and password reset please
        // visit https://go.microsoft.com/fwlink/?LinkID=532713
        var code = await _userManager.GeneratePasswordResetTokenAsync(user);
        var callbackUrl = Url.ResetPasswordCallbackLink(user.Id, code, Request.Scheme);
        await _emailSender.SendEmailAsync(model.Email, "Reset Password",
           $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>");
        return RedirectToAction(nameof(ForgotPasswordConfirmation));
      }

      // If we got this far, something failed, redisplay form
      return View(model);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPasswordConfirmation()
    {
      return View();
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPassword(string code = null)
    {
      if (code == null)
      {
        throw new ApplicationException("A code must be supplied for password reset.");
      }
      var model = new ResetPasswordVM { Code = code };
      return View(model);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(ResetPasswordVM model)
    {
      if (!ModelState.IsValid)
      {
        return View(model);
      }
      var user = await _userManager.FindByEmailAsync(model.Email);
      if (user == null)
      {
        // Don't reveal that the user does not exist
        return RedirectToAction(nameof(ResetPasswordConfirmation));
      }
      var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
      if (result.Succeeded)
      {
        return RedirectToAction(nameof(ResetPasswordConfirmation));
      }
      AddErrors(result);
      return View();
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPasswordConfirmation()
    {
      return View();
    }

    #endregion

    [HttpGet]
    public IActionResult AccessDenied()
    {
      return View();
    }

    #region Helpers

    private void AddErrors(IdentityResult result)
    {
      foreach (var error in result.Errors)
      {
        ModelState.AddModelError(string.Empty, error.Description);
      }
    }

    private IActionResult RedirectToLocal(string returnUrl)
    {
      if (Url.IsLocalUrl(returnUrl))
      {
        return Redirect(returnUrl);
      }
      else
      {
        return RedirectToAction(nameof(HomeController.Index), "Home");
      }
    }

    #endregion

  }
}