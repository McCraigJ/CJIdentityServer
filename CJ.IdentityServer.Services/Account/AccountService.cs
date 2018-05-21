using AutoMapper;
using CJ.IdentityServer.Interfaces;
using CJ.IdentityServer.ServiceModels.Identity;
using CJ.IdentityServer.ServiceModels.Login;
using CJ.IdentityServer.ServiceModels.User;
using CJ.IdentityServer.Services.Data;
using CJ.IdentityServer.Services.Factories;
using CJ.IdentityServer.Services.Models;
using IdentityServer4.Events;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AutoMapper.QueryableExtensions;

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

    private readonly ILogger _logger;
    private readonly IConfiguration _configuration;
    private readonly IConfigurationSection _appSettings;
    private readonly ApplicationDbContext _data;

    public AccountService(
      UserManager<ApplicationUser> userManager,
      RoleManager<IdentityRole> roleManager,
      SignInManager<ApplicationUser> signInManager,
      IIdentityServerInteractionService interaction,
      IAuthenticationSchemeProvider schemeProvider,
      IClientStore clientStore,
      IEventService events,
      ILogger<AccountService> logger,
      IConfiguration configuration,
      ApplicationDbContext data
      )
    {
      _userManager = userManager;
      _roleManager = roleManager;
      _signInManager = signInManager;
      _interaction = interaction;
      _schemeProvider = schemeProvider;
      _clientStore = clientStore;
      _events = events;
      _logger = logger;
      _configuration = configuration;
      _data = data;

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

        return InteractionResultSMFactory.CreateResult(user, result);
      }

      await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials"));
      return InteractionResultSMFactory.CreateResult(null, result);
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

    public async Task<UserSM> FindUserByIdAsync(string userId)
    {
      var user = await _userManager.FindByIdAsync(userId);
      return Mapper.Map<UserSM>(user);
    }
    public async Task<UserSM> FindUserByNameAsync(string userName)
    {
      var user = await _userManager.FindByNameAsync(userName);
      return Mapper.Map<UserSM>(user);
    }

    public async Task<UserSM> FindUserByEmailAsync(string email)
    {
      var user = await _userManager.FindByEmailAsync(email);
      return Mapper.Map<UserSM>(user);
    }

    public async Task<InteractionResultSM> ConfirmEmailAsync(string userId, string code)
    {
      var user = await _userManager.FindByIdAsync(userId);
      if (user == null)
      {
        throw new ApplicationException($"Unable to load user with ID '{userId}'.");
      }
      var result = await _userManager.ConfirmEmailAsync(user, code);

      return InteractionResultSMFactory.CreateResult(user, result);
    }

    public async Task<InteractionResultSM> CreateUserAsync(UserSM user, string password)
    {
      var applicationUser = Mapper.Map<ApplicationUser>(user);
      var createResult = await _userManager.CreateAsync(applicationUser, password);
      user.Id = applicationUser?.Id;
      return InteractionResultSMFactory.CreateResult(user, createResult);
    }

    public async Task<LogoutResultSM> LogoutAsync(string logoutId = null)
    {
      await _signInManager.SignOutAsync();

      if (logoutId == null)
      {
        return null;
      }

      var logout = await _interaction.GetLogoutContextAsync(logoutId);

      return Mapper.Map<LogoutResultSM>(logout);
    }

    public async Task<string> GenerateEmailConfirmationTokenAsync(UserSM user)
    {
      return await _userManager.GenerateEmailConfirmationTokenAsync(Mapper.Map<ApplicationUser>(user));
    }

    public async Task SignInUserAsync(UserSM user, bool isPersistent)
    {
      await _signInManager.SignInAsync(Mapper.Map<ApplicationUser>(user), isPersistent: false);
    }

    public async Task<bool> IsEmailConfirmedAsync(UserSM user)
    {
      return (user != null && !(await _userManager.IsEmailConfirmedAsync(Mapper.Map<ApplicationUser>(user))));
    }

    public async Task<string> GeneratePasswordResetTokenAsync(UserSM user)
    {
      return await _userManager.GeneratePasswordResetTokenAsync(Mapper.Map<ApplicationUser>(user));
    }

    public async Task<InteractionResultSM> ResetPasswordAsync(UserSM user, string code, string password)
    {
      IdentityResult result = await _userManager.ResetPasswordAsync(Mapper.Map<ApplicationUser>(user), code, password);

      return InteractionResultSMFactory.CreateResult(user, result);
    }

    public async Task RaiseLoginSuccessEvent(string provider, string providerUserId, string subjectId, string name)
    {
      await _events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, subjectId, name));
    }

    public bool IsValidReturnUrl(string returnUrl)
    {
      return _interaction.IsValidReturnUrl(returnUrl);
    }

    public async Task<UserSM> GetUserAsync(ClaimsPrincipal principal)
    {
      var applicationUser = await _userManager.GetUserAsync(principal);
      
      return Mapper.Map<UserSM>(applicationUser);
    }

    public async Task<InteractionResultSM> UpdateUserAsync(UserSM user)
    {
      var applicationUser = await _userManager.FindByIdAsync(user.Id);
      applicationUser.FirstName = user.FirstName;
      applicationUser.LastName = user.LastName;
      applicationUser.Email = user.Email;
      applicationUser.PhoneNumber = user.PhoneNumber;
      var result = await _userManager.UpdateAsync(applicationUser);
      return InteractionResultSMFactory.CreateResult(user, result);
    }

    public async Task<InteractionResultSM> ChangePasswordAsync(UserSM user, string oldPassword, string newPassword)
    {
      var applicationUser = await _userManager.FindByIdAsync(user.Id);
      var result = await _userManager.ChangePasswordAsync(applicationUser, oldPassword, newPassword);
      return InteractionResultSMFactory.CreateResult(user, result);
    }

    public IEnumerable<UserSM> GetAllUsers()
    {
      return _data.Users.ProjectTo<UserSM>().ToList();
    }

    public async Task<IEnumerable<string>> GetRolesForUserAsync(UserSM user)
    {
      var applicationUser = Mapper.Map<ApplicationUser>(user);

      return await _userManager.GetRolesAsync(applicationUser);
    }

    public async Task<InteractionResultSM> UpdateUserRolesAsync(string userId, IEnumerable<string> addToRoles, IEnumerable<string> removeFromRoles)
    {
      var applicationUser = await _userManager.FindByIdAsync(userId);
      
      var addResult = await _userManager.AddToRolesAsync(applicationUser, addToRoles);
      var removeResult = await _userManager.RemoveFromRolesAsync(applicationUser, removeFromRoles);

      return InteractionResultSMFactory.CreateResult(applicationUser, addResult);      
    }

    private async Task CreateDefaultData()
    {
      if (Convert.ToBoolean(_appSettings["SeedData"]) == true)
      {
        // Seed roles
        if (!_roleManager.Roles.Any())
        {
          var roles = Enum.GetValues(typeof(UserRole));
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
            var resultAddToRole = await _userManager.AddToRoleAsync(user, UserRole.SystemAdmin.ToString());
          }
        }
      }
    }

    
  }
}
