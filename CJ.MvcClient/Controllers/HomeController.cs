﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using CJ.MvcClient.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using CJ.MvcClient.Filters;

namespace CJ.MvcClient.Controllers
{
  
  public class HomeController : ControllerBase
  {      
    public IActionResult Index()
    {
      return View();
    }

    public IActionResult LoginPartial()
    {      
      return View("_LoginPartial");
    }

    [Authorize]
    public IActionResult About()
    {
      ViewData["Message"] = "Your application description page.";

      return View();
    }

    public IActionResult Contact()
    {
      ViewData["Message"] = "Your contact page.";

      return View();
    }

    public IActionResult Error()
    {
      return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }

    public async Task Logout()
    {
      await HttpContext.SignOutAsync("Cookies");
      await HttpContext.SignOutAsync("oidc");
    }
  }
}
