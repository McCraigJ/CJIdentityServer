using CJ.IdentityServer.ServiceModels.Identity;
using System;
using System.Collections.Generic;
using System.Text;

namespace CJ.IdentityServer.ServiceModels.Identity
{

  public class SecurableResourceSM
  {   
    public bool Enabled { get; set; }
   
    public string Name { get; set; }
   
    public string DisplayName { get; set; }
   
    public string Description { get; set; }
   
    public ICollection<string> UserClaims { get; set; }
  }

  public class IdentityResourceSM : SecurableResourceSM
  {
    public bool Required { get; set; }
    
    public bool Emphasize { get; set; }
   
    public bool ShowInDiscoveryDocument { get; set; }
  }

  public class ApiResourceSM : SecurableResourceSM
  {
    public ICollection<SecretSM> ApiSecrets { get; set; }
   
    public ICollection<ScopeSM> Scopes { get; set; }
  }

  public class SecurableResourcesSM
  {
    public ICollection<IdentityResourceSM> IdentityResources { get; set; }
    public ICollection<ApiResourceSM> ApiResources { get; set; }

    public bool OfflineAccess { get; set; }
  }
}
