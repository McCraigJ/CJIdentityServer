using CJ.Common.Interfaces;
using CJ.Common.ServiceModels.Notification;
using System.Threading.Tasks;

namespace CJ.Common.EmailNotification
{
  public class EmailNotifierService : INotifierService
  {
    public async Task<NotifierResponseSM> SendNotificationAsync(MessageSM message)
    {

      return new NotifierResponseSM { Success = true };
    }    
  }
}
