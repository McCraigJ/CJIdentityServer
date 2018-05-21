using CJ.IdentityServer.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Web.Attributes
{
  public class CJAuthoriseAttribute : AuthorizeAttribute, IAuthorizationFilter
  {
    //private readonly IAccountService _accountService;

    public CJAuthoriseAttribute()
    {
      //_accountService = accountService;
    }
    public void OnAuthorization(AuthorizationFilterContext context)
    {
      var accountService = (IAccountService)context.HttpContext.RequestServices.GetService(typeof(IAccountService)); // <IAccountService>();
      var user = accountService.GetUserAsync(context.HttpContext.User).Result;
      var roles = accountService.GetRolesForUserAsync(user).Result;
      if (!roles.Contains(Roles))
      {
        context.Result = new StatusCodeResult((int)System.Net.HttpStatusCode.Forbidden);
        return;
      }

    }
  }
}
