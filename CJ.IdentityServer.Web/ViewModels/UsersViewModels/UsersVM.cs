using CJ.IdentityServer.ServiceModels.User;
using System.Collections.Generic;

namespace CJ.IdentityServer.Web.ViewModels.UsersViewModels
{
  public class UsersVM
  {
    public IEnumerable<UserSM> Users { get; set; }
  }
}
