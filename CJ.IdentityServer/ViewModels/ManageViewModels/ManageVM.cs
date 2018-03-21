using CJ.IdentityServer.Models;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.ViewModels.ManageViewModels
{
  public class ManageVM
  {
    public string Username { get; set; }

    public bool IsEmailConfirmed { get; set; }

    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Phone]
    [Display(Name = "Phone number")]
    public string PhoneNumber { get; set; }

    public string StatusMessage { get; set; }

    [StringLength(15, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 0)]
    [Display(Name = "First Name")]
    public string FirstName { get; set; }

    [StringLength(15, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 0)]
    [Display(Name = "Last Name")]
    public string LastName { get; set; }

    [ReadOnly(true)]
    [Display(Name = "Login Type")]
    public UserType UserType { get; set; }
    
    [ReadOnly(true)]
    [Display(Name = "User Role")]
    public string UserRole { get; set; }
  }
}
