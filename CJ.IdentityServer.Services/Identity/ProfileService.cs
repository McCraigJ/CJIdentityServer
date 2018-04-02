using CJ.IdentityServer.Interfaces;
using CJ.IdentityServer.ServiceModels.User;
using IdentityServer4.Models;
using IdentityServer4.Services;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Services.Identity
{
  public class ProfileService : IProfileService
  {    
    private readonly IAccountService _accountService;    

    public ProfileService(
      IAccountService accountService)
    {
      _accountService = accountService;
    }

    public Task GetProfileDataAsync(ProfileDataRequestContext context)
    {
      //>Processing
      var user = _accountService.GetUserAsync(context.Subject).Result;
      var userRoles = _accountService.GetRolesForUserAsync(user).Result;
      var isAdmin = userRoles.Any(x => x == UserSM.SysAdminRoleName);
      
      var claims = new List<Claim>
      {
          new Claim("name", user.UserName),
          new Claim("admin", isAdmin.ToString()),
          new Claim("firstname", user.FirstName ?? "")
      };

      context.IssuedClaims.AddRange(claims);

      //>Return
      return Task.FromResult(0);
    }

    public Task IsActiveAsync(IsActiveContext context)
    {
      context.IsActive = true;
      
      //>Return
      return Task.FromResult(0);
    }
  }
}
