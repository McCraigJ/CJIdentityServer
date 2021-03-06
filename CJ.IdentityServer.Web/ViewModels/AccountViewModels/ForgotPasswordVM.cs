﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Web.ViewModels.AccountViewModels
{
  public class ForgotPasswordVM
  {
    [Required]
    [EmailAddress]
    public string Email { get; set; }
  }
}
