﻿using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Models
{
  public class ApplicationUser : IdentityUser
  {
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public int UserType { get; set; }
    public string UserRole { get; set; }

    public ApplicationUser()
    {
      UserRole = UserRoles.Standard.ToString();
    }
  }
}