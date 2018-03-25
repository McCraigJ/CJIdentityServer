using System;

namespace CJ.IdentityServer.ServiceModels.Login
{
  public class LoginSM
  {
    public string Username { get; set; }
    public string Password { get; set; }   
    public bool RememberLogin { get; set; }
    public string ReturnUrl { get; set; }
  }
}
