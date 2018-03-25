using CJ.IdentityServer.ServiceModels.User;
using System;
using System.Collections.Generic;
using System.Text;

namespace CJ.IdentityServer.ServiceModels.Identity
{
  public class InteractionResultSM
  {
    public bool Succeeded { get; set; }
    
    public UserSM User { get; set; }

    public Dictionary<string, string> Errors { get; set; }
  }
}
