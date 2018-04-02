using System;
using System.Collections.Generic;
using System.Text;

namespace CJ.IdentityServer.ServiceModels.User
{

  public enum UserType
  {
    Standard = 1,
    Windows = 2
  }

  public enum UserRoles
  {
    Standard = 1,
    SystemAdmin = 2
  }

  public class UserSM
  {
    public string Id { get; set; }
    public string UserName { get; set; }
    public string Email { get; set; }
    public string PhoneNumber { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public int UserType { get; set; }
    public bool IsEmailConfirmed { get; set; }    
  }
}
