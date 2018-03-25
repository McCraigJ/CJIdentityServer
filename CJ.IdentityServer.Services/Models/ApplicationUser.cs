using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Text;

namespace CJ.IdentityServer.Services.Models
{
  public class ApplicationUser : IdentityUser
  {
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public int UserType { get; set; }
  }
}
