using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Web.ViewModels
{
  public class StatusMessageVM
  {
    private bool _success;
    private string _statusMessage;

    public bool Success { get { return _success; } }
    public string StatusMessage { get { return _statusMessage; } }

    public StatusMessageVM(bool success, string statusMessage)
    {
      _success = success;
      _statusMessage = statusMessage;
    }
  }  
}
