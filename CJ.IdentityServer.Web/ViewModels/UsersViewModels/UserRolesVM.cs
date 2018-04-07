using CJ.IdentityServer.ServiceModels.User;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Web.ViewModels.UsersViewModels
{
  public class UserRolesVM : ViewModelBase
  {
    public string Id { get; set; }

    [Display(Name = "User Name")]
    [ReadOnly(true)]
    public string UserName { get; set; }

    [Display(Name = "Email")]
    [ReadOnly(true)]
    public string Email { get; set; }

    [Display(Name = "Name")]
    [ReadOnly(true)]
    public string Name { get; set; }

    public List<CheckBoxListItemVM> UserRoles { get; set; }
  }

}
