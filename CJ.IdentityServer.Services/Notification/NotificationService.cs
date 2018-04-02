using CJ.Common.Interfaces;
using CJ.Common.ServiceModels.Notification;
using CJ.IdentityServer.Interfaces;
using CJ.IdentityServer.ServiceModels.User;
using Microsoft.Extensions.Configuration;
using System;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace CJ.Common.EmailNotification
{
  public class NotificationService : INotificationService
  {
    private readonly IConfigurationSection _appSettings;
    private readonly IAccountService _accountService;
    private readonly INotifierService _notifierService;

    public NotificationService(
      IConfiguration configuration,
      IAccountService accountService,
      INotifierService notifierService
      )
    {
      _accountService = accountService;
      _appSettings = configuration.GetSection("AppSettings");
      _notifierService = notifierService;
    }

    public async Task<NotifierResponseSM> SendForgotPasswordNotificationAsync(UserSM user, string callbackUrl)
    {
      
      if (user != null)
      {
        var message = new MessageSM
        {
          From = GetFrom(),
          To = user.Email,
          GreetingName = GetGreetingName(user),
          Subject = "Reset Password",
          MessageBody = $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>",          
        };
        var response = await _notifierService.SendNotificationAsync(message);        
        return response;
      }
      
      return null;      
    }

    public async Task<NotifierResponseSM> SendConfirmationNotificationAsync(UserSM user, string callbackUrl)
    {
      if (user != null)
      {
        var message = new MessageSM
        {
          From = GetFrom(),
          To = user.Email,
          GreetingName = GetGreetingName(user),
          Subject = "Confirm your email",
          MessageBody = $"Please confirm your account by clicking this link: <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>link</a>",
        };
        var response = await _notifierService.SendNotificationAsync(message);
        return response;
      }

      return null;
    }

    private string GetGreetingName(UserSM user)
    {
      if (string.IsNullOrEmpty(user.FirstName))
      {
        return user.UserName;
      }
      return user.FirstName;
    }

    private string GetFrom()
    {
      return _appSettings["NotificationFrom"];
    }

    
  }
}
