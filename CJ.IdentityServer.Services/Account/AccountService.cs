using CJ.IdentityServer.Interfaces.Account;
using CJ.IdentityServer.ServiceModels;
using CJ.IdentityServer.ServiceModels.Login;
using CJ.IdentityServer.ServiceModels.User;
using CJ.IdentityServer.Services.Data;
using CJ.IdentityServer.Services.Models;
using IdentityServer4.Events;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Services.Account
{
  public class AccountService : IAccountService
  {
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    private readonly IIdentityServerInteractionService _interaction;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IClientStore _clientStore;
    private readonly IEventService _events;

    //private readonly IEmailSender _emailSender;
    private readonly ILogger _logger;
    private readonly IConfiguration _configuration;
    private readonly IConfigurationSection _appSettings;

    public AccountService(
      UserManager<ApplicationUser> userManager,
      RoleManager<IdentityRole> roleManager,
      SignInManager<ApplicationUser> signInManager,
      IIdentityServerInteractionService interaction,
      IAuthenticationSchemeProvider schemeProvider,
      IClientStore clientStore,
      IEventService events,
      //IEmailSender emailSender,
      ILogger<AccountService> logger,
      IConfiguration configuration)
    {
      _userManager = userManager;
      _roleManager = roleManager;
      _signInManager = signInManager;
      _interaction = interaction;
      _schemeProvider = schemeProvider;
      _clientStore = clientStore;
      _events = events;
      //_emailSender = emailSender;
      _logger = logger;
      _configuration = configuration;

      _appSettings = configuration.GetSection("AppSettings");
    }

    public async Task SeedData()
    {
      await CreateDefaultData();      
    }
    
    public async Task<InteractionResultSM> LoginAsync(LoginSM model)
    {
      var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberLogin, lockoutOnFailure: false);
      if (result.Succeeded)
      {
        var user = await _signInManager.UserManager.FindByNameAsync(model.Username);
        await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName));

        return new InteractionResultSM { Succeeded = true, User = AutoMapper.Mapper.Map<UserSM>(user) };
      }

      await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials"));
      return new InteractionResultSM { Succeeded = false, User = null, Errors = null };      
    }

    public async Task<string> CancelLoginAsync(string returnUrl)
    {
      var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
      if (context != null)
      {
        // if the user cancels, send a result back into IdentityServer as if they 
        // denied the consent (even if this client does not require consent).
        // this will send back an access denied OIDC error response to the client.
        await _interaction.GrantConsentAsync(context, ConsentResponse.Denied);

        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
        return returnUrl;
      }
      else
      {
        // since we don't have a valid context, then we just go back to the home page
        return "~/";
      }
    }    

    public async Task<UserSM> FindUserByNameAsync(string userName)
    {
      var user = await _userManager.FindByNameAsync(userName);
      return AutoMapper.Mapper.Map<UserSM>(user);      
    }

    public async Task<UserSM> FindUserByEmailAsync(string email)
    {
      var user = await _userManager.FindByEmailAsync(email);
      return AutoMapper.Mapper.Map<UserSM>(user);
    }

    public async Task<InteractionResultSM> ConfirmEmailAsync(string userId, string code)
    {      
      var user = await _userManager.FindByIdAsync(userId);
      if (user == null)
      {
        throw new ApplicationException($"Unable to load user with ID '{userId}'.");
      }
      var result = await _userManager.ConfirmEmailAsync(user, code);

      if (result.Succeeded)
      {
        return new InteractionResultSM { Succeeded = true, User = AutoMapper.Mapper.Map<UserSM>(user) };
      }
      return new InteractionResultSM { Succeeded = false, User = null, Errors = result.Errors.ToDictionary(x => x.Code, y => y.Description) };
    }

    public async Task<InteractionResultSM> CreateUserAsync(UserSM user, string password)
    {
      var applicationUser = AutoMapper.Mapper.Map<ApplicationUser>(user);
      var createResult = await _userManager.CreateAsync(applicationUser, password);      
      if (createResult.Succeeded)
      {
        return new InteractionResultSM { Succeeded = true, User = AutoMapper.Mapper.Map<UserSM>(user) };
      }
      return new InteractionResultSM { Succeeded = false, User = null, Errors = createResult.Errors.ToDictionary(x => x.Code, y => y.Description) };
    }

    public async Task<LogoutResultSM> LogoutAsync(string logoutId = null)
    {
      await _signInManager.SignOutAsync();

      if (logoutId == null)
      {
        return null;
      }

      var logout = await _interaction.GetLogoutContextAsync(logoutId);

      return AutoMapper.Mapper.Map<LogoutResultSM>(logout);
    }

    public async Task<string> GenerateEmailConfirmationTokenAsync(UserSM user)
    {
      return await _userManager.GenerateEmailConfirmationTokenAsync(AutoMapper.Mapper.Map<ApplicationUser>(user));
    }

    public async Task SignInUserAsync(UserSM user, bool isPersistent)
    {
      await _signInManager.SignInAsync(AutoMapper.Mapper.Map<ApplicationUser>(user), isPersistent: false);
    }

    public async Task<bool> IsEmailConfirmedAsync(UserSM user)
    {
      return (user != null && !(await _userManager.IsEmailConfirmedAsync(AutoMapper.Mapper.Map<ApplicationUser>(user))));
    }

    public async Task<string> GeneratePasswordResetTokenAsync(UserSM user)
    {
      return await _userManager.GeneratePasswordResetTokenAsync(AutoMapper.Mapper.Map<ApplicationUser>(user));
    }
      
    public async Task<InteractionResultSM> ResetPasswordAsync(UserSM user, string code, string password)
    {
      var result = await _userManager.ResetPasswordAsync(AutoMapper.Mapper.Map<ApplicationUser>(user), code, password);

      if (result.Succeeded)
      {
        return new InteractionResultSM { Succeeded = true, User = user };
      }
      return new InteractionResultSM { Succeeded = false, User = null, Errors = result.Errors.ToDictionary(x => x.Code, y => y.Description) };
    }

    public async Task RaiseLoginSuccessEvent(string provider, string providerUserId, string subjectId, string name)
    {
      await _events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, subjectId, name));      
    }


    private async Task CreateDefaultData()
    {
      if (Convert.ToBoolean(_appSettings["SeedData"]) == true)
      {
        // Seed roles
        if (!_roleManager.Roles.Any())
        {
          var roles = Enum.GetValues(typeof(UserRoles));
          foreach (var r in roles)
          {
            var result = await _roleManager.CreateAsync(new IdentityRole { Name = r.ToString() });
          }
        }

        // Seed default user
        if (!_userManager.Users.Any())
        {
          var user = new ApplicationUser
          {
            UserName = "admin",
            UserType = (int)UserType.Standard
          };
          var resultUser = await _userManager.CreateAsync(user, "_Install123");
          if (resultUser.Succeeded)
          {
            var resultAddToRole = await _userManager.AddToRoleAsync(user, UserRoles.SystemAdmin.ToString());
          }
        }
      }
    }

  }
}
