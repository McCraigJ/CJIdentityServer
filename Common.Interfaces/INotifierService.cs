using CJ.Common.ServiceModels.Notification;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace CJ.Common.Interfaces
{
  public interface INotifierService
  {
    Task<NotifierResponseSM> SendNotificationAsync(MessageSM message);
  }
}
