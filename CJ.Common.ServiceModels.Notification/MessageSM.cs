using System;
using System.Collections.Generic;
using System.Text;

namespace CJ.Common.ServiceModels.Notification
{
  public class MessageSM
  {
    public string From { get; set; }
    public string To { get; set; }
    public string GreetingName { get; set; }
    public string Subject { get; set; }
    public string MessageBody { get; set; }
  }
}
