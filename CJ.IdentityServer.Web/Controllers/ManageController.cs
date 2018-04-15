using AutoMapper;
using CJ.IdentityServer.Interfaces;
using CJ.IdentityServer.ServiceModels.User;
using CJ.IdentityServer.Web.Helpers;
using CJ.IdentityServer.Web.ViewModels;
using CJ.IdentityServer.Web.ViewModels.ManageViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Web.Controllers
{
  [Authorize]
  [Route("[controller]/[action]")]
  public class ManageController : ControllerBase
  {
    private readonly IAccountService _accountService;
    private readonly INotificationService _notificationService;
    private readonly ILogger _logger;
    private readonly UrlEncoder _urlEncoder;

    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
    private const string RecoveryCodesKey = nameof(RecoveryCodesKey);

    public ManageController(
      IAccountService accountService,            
      INotificationService notificationService,      
      ILogger<ManageController> logger,
      UrlEncoder urlEncoder
      )
    {
      _accountService = accountService;
      _notificationService = notificationService;
      _logger = logger;
      _urlEncoder = urlEncoder;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
      var user = await GetLoggedInUserAsync();

      var model = Mapper.Map<ManageVM>(user);
      model.StatusMessage = StatusMessage;

      return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Index(ManageVM model)
    {
      if (!ModelState.IsValid)
      {
        return View(model);
      }

      var user = await GetLoggedInUserAsync();

      // Update the user with the values from the model
      user.Email = model.Email;
      user.PhoneNumber = model.PhoneNumber;
      user.FirstName = model.FirstName;
      user.LastName = model.LastName;

      var updateResult = await _accountService.UpdateUserAsync(user);
      if (!updateResult.Succeeded)
      {
        throw new ApplicationException(@"Unexpected error occurred updating user");
      }

      StatusMessage = new StatusMessageVM(true, "Your profile has been updated");
      return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SendVerificationEmail(ManageVM model)
    {
      if (!ModelState.IsValid)
      {
        return View(model);
      }

      var user = await GetLoggedInUserAsync();

      var code = await _accountService.GenerateEmailConfirmationTokenAsync(user);
      var callbackUrl = Url.EmailConfirmationLink(user.Id, code, Request.Scheme);
      var email = user.Email;
      var response = await _notificationService.SendConfirmationNotificationAsync(user, callbackUrl);
      if (response.Success)
      {
        StatusMessage = new StatusMessageVM(true, "Verification email sent. Please check your email.");
      } else
      {
        StatusMessage = new StatusMessageVM(false, "An error occurred");
      }

      
      return RedirectToAction(nameof(Index));
    }

    [HttpGet]
    public async Task<IActionResult> ChangePassword()
    {
      var user = await GetLoggedInUserAsync();

      var model = new ChangePasswordVM { StatusMessage = StatusMessage };
      return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordVM model)
    {
      if (!ModelState.IsValid)
      {
        return View(model);
      }

      var user = await GetLoggedInUserAsync();

      if (ViewHelper.GetIdentityProvider(User.Claims) != "local")
      {
        throw new ApplicationException($"Cannot set a password for a non-local user '{User.Identity.Name}'.");
      }

      var changePasswordResult = await _accountService.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
      if (!changePasswordResult.Succeeded)
      {
        AddErrors(changePasswordResult.Errors);
        return View(model);
      }

      await _accountService.SignInUserAsync(user, isPersistent: false);
      _logger.LogInformation("User changed their password successfully.");
      StatusMessage = new StatusMessageVM(true, "Your password has been changed.");

      return RedirectToAction(nameof(ChangePassword));
    }

    #region Helpers

    private async Task<UserSM> GetLoggedInUserAsync()
    {
      var user = await _accountService.GetUserAsync(User);
      if (user == null)
      {
        throw new ApplicationException($"Unable to load logged in user.");
      }
      return user;
    }

    #endregion
  }
}
