using AutoMapper;
using CJ.IdentityServer.Interfaces;
using CJ.IdentityServer.ServiceModels.Login;
using CJ.IdentityServer.ServiceModels.User;
using CJ.IdentityServer.Web.Factories;
using CJ.IdentityServer.Web.Models;
using CJ.IdentityServer.Web.ViewModels.AccountViewModels;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Web.Controllers
{
  public class AccountController : ControllerBase
  {
    private readonly IAccountService _accountService;
    private readonly ISecurableService _securableService;
    private readonly INotificationService _notificationService;
    private readonly ILogger _logger;
    private readonly IAuthenticationSchemeProvider _schemeProvider;

    public AccountController(
        IAccountService accountService,
        ISecurableService securableService,
        IAuthenticationSchemeProvider schemeProvider,
        INotificationService notificationService, 
        ILogger<AccountController> logger)
    {
      _accountService = accountService;
      _securableService = securableService;
      _schemeProvider = schemeProvider;
      _notificationService = notificationService;      
      _logger = logger;
      
    }

    #region Seed Data

    public async Task<IActionResult> SeedData()
    {     
      await _accountService.SeedData();
      return RedirectToAction("Login");
    }

    #endregion

    #region Login

    public async Task<IActionResult> Login(string returnUrl)
    {
      var vm = await LoginVMFactory.BuildLoginVMAsync(_securableService, _schemeProvider, returnUrl);

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
        var returnUrl = await _accountService.CancelLoginAsync(model.ReturnUrl);
        return Redirect(returnUrl);
      }

      if (ModelState.IsValid)
      {
        var result = await _accountService.LoginAsync(AutoMapper.Mapper.Map<LoginSM>(model));
        if (result.Succeeded)
        {
          // only set explicit expiration here if user chooses "remember me". 
          // otherwise we rely upon expiration configured in cookie middleware.
          AuthenticationProperties props = null;
          if (AccountOptionsOM.AllowRememberLogin && model.RememberLogin)
          {
            props = new AuthenticationProperties
            {
              IsPersistent = true,
              ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptionsOM.RememberMeLoginDuration)
            };
          };

          // issue authentication cookie with subject ID and username -- and roles

          
          var roles = await _accountService.GetRolesForUserAsync(result.User);

          var claimsId = new ClaimsIdentity();
          
          claimsId.AddClaim(new Claim(JwtClaimTypes.Subject, result.User.Id));
          claimsId.AddClaim(new Claim(JwtClaimTypes.Name, result.User.UserName));
          var roleClaims = roles.Select(x => new Claim(JwtClaimTypes.Role, x));
          claimsId.AddClaims(roleClaims);

          await HttpContext.SignInAsync(
            //result.User.Id, 
            new ClaimsPrincipal(claimsId),
            props); //result.User.UserName, props);

          // make sure the returnUrl is still valid, and if so redirect back to authorize endpoint or a local page
          // the IsLocalUrl check is only necessary if you want to support additional local pages, otherwise IsValidReturnUrl is more strict
          if (_accountService.IsValidReturnUrl(model.ReturnUrl) || Url.IsLocalUrl(model.ReturnUrl))
          {
            return Redirect(model.ReturnUrl);
          }

          return Redirect("~/");
        }        

        ModelState.AddModelError("", AccountOptionsOM.InvalidCredentialsErrorMessage);
        
      }
      // something went wrong, show form with error
      var vm = await LoginVMFactory.BuildLoginVMAsync(_securableService, _schemeProvider, model);
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

      var externalUser = result.Principal;

      // try to determine the unique id of the external user (issued by the provider)
      // the most common claim type for that are the sub claim and the NameIdentifier
      // depending on the external provider, some other claim type might be used
      var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                        externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                        throw new Exception("Unknown userid");

      // remove the user id claim so we don't include it as an extra claim if/when we provision the user
      var claims = externalUser.Claims.ToList();
      claims.Remove(userIdClaim);

      var provider = result.Properties.Items["scheme"];
      var providerUserId = userIdClaim.Value;
      
      var userName = providerUserId.Split('\\').LastOrDefault();
      if (string.IsNullOrEmpty(userName))
      {
        userName = providerUserId;
      }
      var user = await _accountService.FindUserByNameAsync(userName);
      if (user == null)
      {
        user = new UserSM { UserName = userName, Id = providerUserId, UserType = (int)UserType.Windows };
        await _accountService.CreateUserAsync(user, Config.WindowsUserPassword);
      }

            
      // this allows us to collect any additonal claims or properties
      // for the specific prtotocols used and store them in the local auth cookie.
      // this is typically used to store data needed for signout from those protocols.
      var additionalLocalClaims = new List<Claim>();
      var localSignInProps = new AuthenticationProperties();
      ProcessLoginCallbackForOidc(result, additionalLocalClaims, localSignInProps);

      // issue authentication cookie for user      
      await _accountService.RaiseLoginSuccessEvent(provider, providerUserId, user.UserName, user.UserName);
      await HttpContext.SignInAsync(user.Id, user.UserName, provider, localSignInProps, additionalLocalClaims.ToArray());

      // delete temporary cookie used during external authentication
      await HttpContext.SignOutAsync(IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme);

      // validate return URL and redirect back to authorization endpoint or a local page
      var returnUrl = result.Properties.Items["returnUrl"];
      if (_accountService.IsValidReturnUrl(returnUrl) || Url.IsLocalUrl(returnUrl))
      {
        return Redirect(returnUrl);
      }

      return Redirect("~/");
    }

    private async Task<IActionResult> ProcessWindowsLoginAsync(string returnUrl)
    {
      // see if windows auth has already been requested and succeeded
      var result = await HttpContext.AuthenticateAsync(AccountOptionsOM.WindowsAuthenticationSchemeName);
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
                        { "scheme", AccountOptionsOM.WindowsAuthenticationSchemeName },
                    }
        };

        var id = new ClaimsIdentity(AccountOptionsOM.WindowsAuthenticationSchemeName);
        id.AddClaim(new Claim(JwtClaimTypes.Subject, wp.Identity.Name));
        id.AddClaim(new Claim(JwtClaimTypes.Name, wp.Identity.Name));

        // add the groups as claims -- be careful if the number of groups is too large
        if (AccountOptionsOM.IncludeWindowsGroups)
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
        return Challenge(AccountOptionsOM.WindowsAuthenticationSchemeName);
      }
    }

    #endregion

    #region Logout

    [HttpGet]
    public async Task<IActionResult> Logout(string logoutId)
    {
      var logoutResult = await _accountService.LogoutAsync(logoutId);
      
      _logger.LogInformation("User logged out.");
      
      var vm = new LoggedOutVM
      {
        AutomaticRedirectAfterSignOut = AccountOptionsOM.AutomaticRedirectAfterSignOut,
        PostLogoutRedirectUri = logoutResult?.PostLogoutRedirectUri,
        ClientName = string.IsNullOrEmpty(logoutResult?.ClientName) ? logoutResult?.ClientId : logoutResult?.ClientName,
        SignOutIframeUrl = logoutResult?.SignOutIframeUrl,
        LogoutId = logoutId
      };

      return View("LoggedOut", vm);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
      await _accountService.LogoutAsync();
      
      _logger.LogInformation("User logged out.");
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
        var user = Mapper.Map<UserSM>(model);
        user.UserType = (int)UserType.Standard;
        
        var result = await _accountService.CreateUserAsync(user, model.Password);
        if (result.Succeeded)
        {
          _logger.LogInformation("User created a new account with password.");

          var code = await _accountService.GenerateEmailConfirmationTokenAsync(user);
          var callbackUrl = Url.EmailConfirmationLink(user.Id, code, Request.Scheme);
          await _notificationService.SendConfirmationNotificationAsync(user, callbackUrl);          

          await _accountService.SignInUserAsync(user, false);
          _logger.LogInformation("User created a new account with password.");
          return RedirectToLocal(returnUrl);
        }
        AddErrors(result.Errors);
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

      var result = await _accountService.ConfirmEmailAsync(userId, code);
      
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

        var user = await _accountService.FindUserByEmailAsync(model.Email);

        if (!(await _accountService.IsEmailConfirmedAsync(user)))
        {
          // Don't reveal that the user does not exist or is not confirmed
          return RedirectToAction(nameof(ForgotPasswordConfirmation));
        }
                
        // For more information on how to enable account confirmation and password reset please
        // visit https://go.microsoft.com/fwlink/?LinkID=532713

        var code = await _accountService.GeneratePasswordResetTokenAsync(user);
        var callbackUrl = Url.ResetPasswordCallbackLink(user.Id, code, Request.Scheme);

        await _notificationService.SendForgotPasswordNotificationAsync(user, callbackUrl);        
        
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
      var user = await _accountService.FindUserByEmailAsync(model.Email);
      if (user == null)
      {
        // Don't reveal that the user does not exist
        return RedirectToAction(nameof(ResetPasswordConfirmation));
      }
      var result = await _accountService.ResetPasswordAsync(user, model.Code, model.Password);      
      if (result.Succeeded)
      {
        return RedirectToAction(nameof(ResetPasswordConfirmation));
      }
      AddErrors(result.Errors);
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
    
    private void ProcessLoginCallbackForOidc(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
    {
      // if the external system sent a session id claim, copy it over
      // so we can use it for single sign-out
      var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
      if (sid != null)
      {
        localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
      }

      // if the external provider issued an id_token, we'll keep it for signout
      var id_token = externalResult.Properties.GetTokenValue("id_token");
      if (id_token != null)
      {
        localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = id_token } });
      }
    }

    #endregion

  }
}