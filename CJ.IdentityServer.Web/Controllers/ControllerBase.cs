using CJ.IdentityServer.Web.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Web.Controllers
{
  public class ControllerBase : Controller
  {
    [TempData]
    public string StatusMessageJson { get
      {
        return JsonConvert.SerializeObject(StatusMessage);
      }
      set
      {
        if (!string.IsNullOrEmpty(value))
        {
          StatusMessage = JsonConvert.DeserializeObject<StatusMessageVM>(value);
        }
      }
    }

    public StatusMessageVM StatusMessage { get; set; }

    protected void AddErrors(Dictionary<string, string> errors)
    {
      foreach (var error in errors)
      {
        ModelState.AddModelError(string.Empty, error.Value);
      }
    }

    protected IActionResult RedirectToLocal(string returnUrl)
    {
      if (Url.IsLocalUrl(returnUrl))
      {
        return Redirect(returnUrl);
      }
      else
      {
        return RedirectToAction(nameof(HomeController.Index), "Home");
      }
    }

  }
}
