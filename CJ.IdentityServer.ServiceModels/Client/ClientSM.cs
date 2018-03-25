using System;
using System.Collections.Generic;
using System.Text;

namespace CJ.IdentityServer.ServiceModels.Client
{
  public class ClientSM
  {
    public bool EnableLocalLogin { get; set; }
    public ICollection<string> IdentityProviderRestrictions { get; set; }
    public string ClientName;
    public string ClientId;
    public string ClientUri;
    public string LogoUri;
    public bool AllowRememberConsent;
  }
}
