using CJ.IdentityServer.ServiceModels;
using CJ.IdentityServer.ServiceModels.Client;
using CJ.IdentityServer.ServiceModels.Identity;
using CJ.IdentityServer.ServiceModels.Login;
using CJ.IdentityServer.ServiceModels.User;
using System;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Interfaces
{
  public interface IAccountService
  {
    Task SeedData();

    Task<InteractionResultSM> LoginAsync(LoginSM model);

    Task<string> CancelLoginAsync(string returnUrl);

    Task<UserSM> FindUserByNameAsync(string userName);

    Task<UserSM> FindUserByEmailAsync(string email);

    Task<InteractionResultSM> ConfirmEmailAsync(string userId, string code);

    Task<InteractionResultSM> CreateUserAsync(UserSM user, string password);

    Task<LogoutResultSM> LogoutAsync(string logoutId = null);

    Task RaiseLoginSuccessEvent(string provider, string providerUserId, string subjectId, string name);

    Task<string> GenerateEmailConfirmationTokenAsync(UserSM user);

    Task SignInUserAsync(UserSM user, bool isPersistent);

    Task<bool> IsEmailConfirmedAsync(UserSM user);

    Task<string> GeneratePasswordResetTokenAsync(UserSM user);

    Task<InteractionResultSM> ResetPasswordAsync(UserSM user, string code, string password);
    
    bool IsValidReturnUrl(string returnUrl);
  }
}
