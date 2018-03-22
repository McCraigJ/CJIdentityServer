using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace CJ.IdentityServer.Controllers
{
  public class HomeController : Controller
  {    
    private readonly IConfigurationSection _appSettings;

    public HomeController(IConfiguration configuration)
    {      
      _appSettings = configuration.GetSection("AppSettings");
    }

    public IActionResult Index()
    {
      var defaultHomePage = _appSettings["DefaultHomePage"];
      if (!string.IsNullOrEmpty(defaultHomePage))
      {
        return Redirect(defaultHomePage);
      }
      return View();
    }
  }
}