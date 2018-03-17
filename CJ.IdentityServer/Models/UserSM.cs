using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Models
{
  public enum UserType
  {
    Standard = 1,
    Windows = 2
  }
  public class UserSM
  {
    public int Id { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string ExternalUserId { get; set; }
    public string Role { get; set; }
    public string Email { get; set; }
    public UserType UserType { get; set; }
  }
}
