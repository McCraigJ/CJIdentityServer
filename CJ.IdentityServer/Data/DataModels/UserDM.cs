using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Data.DataModels
{
  [Table(name: "Users")]
  public class UserDM
  {
    [Key]
    public int Id { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string ExternalUserId { get; set; }
    public string Role { get; set; }
    public string Email { get; set; }
    
    public int UserType { get; set; }
  }
}
