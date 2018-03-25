using System;
using System.Collections.Generic;
using System.Text;

namespace CJ.IdentityServer.ServiceModels.Identity
{
  public class SecretSM
  {
    public string Description { get; set; }

    public string Value { get; set; }

    public DateTime? Expiration { get; set; }

    public string Type { get; set; }
  }
}
