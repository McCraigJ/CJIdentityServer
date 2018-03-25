using System;
using System.Collections.Generic;
using System.Text;

namespace CJ.IdentityServer.ServiceModels.Identity
{
  public class ContentResponseSM
  {

    public static ContentResponseSM Denied
    {
      get
      {
        return new ContentResponseSM
        {
          RememberConsent = false,
          ScopesConsented = null
        };
      }
    }

    private bool _granted;

    public bool Granted { get; }

    public IEnumerable<string> ScopesConsented { get; set; }

    public bool RememberConsent { get; set; }
  }
}
