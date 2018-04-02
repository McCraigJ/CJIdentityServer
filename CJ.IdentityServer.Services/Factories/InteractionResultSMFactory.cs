using CJ.IdentityServer.ServiceModels.Identity;
using CJ.IdentityServer.ServiceModels.User;
using CJ.IdentityServer.Services.Models;
using Microsoft.AspNetCore.Identity;
using System.Linq;

namespace CJ.IdentityServer.Services.Factories
{
  public static class InteractionResultSMFactory
  {
    public static InteractionResultSM CreateResult(ApplicationUser user, IdentityResult identityResult)
    {
      if (identityResult.Succeeded)
      {
        return new InteractionResultSM { Succeeded = true, User = AutoMapper.Mapper.Map<UserSM>(user) };
      }
      return new InteractionResultSM { Succeeded = false, User = null, Errors = identityResult.Errors.ToDictionary(x => x.Code, y => y.Description) };
    }

    public static InteractionResultSM CreateResult(UserSM user, IdentityResult identityResult)
    {
      if (identityResult.Succeeded)
      {
        return new InteractionResultSM { Succeeded = true, User = user };
      }
      return new InteractionResultSM { Succeeded = false, User = null, Errors = identityResult.Errors.ToDictionary(x => x.Code, y => y.Description) };
    }

    public static InteractionResultSM CreateResult(ApplicationUser user, SignInResult signInResult)
    {
      if (signInResult.Succeeded)
      {        
        return new InteractionResultSM { Succeeded = true, User = AutoMapper.Mapper.Map<UserSM>(user) };
      }
      
      return new InteractionResultSM { Succeeded = false, User = null };
    }
  }
}
