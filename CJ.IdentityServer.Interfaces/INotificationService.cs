using CJ.Common.ServiceModels.Notification;
using CJ.IdentityServer.ServiceModels.User;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Interfaces
{
  public interface INotificationService
  {
    Task<NotifierResponseSM> SendForgotPasswordNotificationAsync(UserSM user, string callbackUrl);

    Task<NotifierResponseSM> SendConfirmationNotificationAsync(UserSM user, string callbackUrl);
  }
}
