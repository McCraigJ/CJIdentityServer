using CJ.IdentityServer.ServiceModels.User;
using System.Collections.Generic;

namespace CJ.IdentityServer.Web.ViewModels.UsersViewModels
{
  public class UsersVM : ViewModelBase
  {
    public IEnumerable<UserSM> Users { get; set; }
  }
}
