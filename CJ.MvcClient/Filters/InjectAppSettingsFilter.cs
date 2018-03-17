using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.MvcClient.Filters
{
  public class InjectAppSettingsFilterAttribute : IActionFilter
  {
    private readonly IConfigurationSection _appSettings;

    public InjectAppSettingsFilterAttribute(IConfiguration configuration)
    {
      _appSettings = configuration.GetSection("AppSettings");

      
    }

    public void OnActionExecuted(ActionExecutedContext context)
    {
      var executingController = context.Controller as Controller;
      executingController.ViewData["IdentityServerAuthority"] = _appSettings["IdentityServerAuthority"];
    }

    public void OnActionExecuting(ActionExecutingContext context)
    {      
      
    }
  }
}
