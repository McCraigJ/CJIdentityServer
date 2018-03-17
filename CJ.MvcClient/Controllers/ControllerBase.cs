using CJ.MvcClient.Filters;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.MvcClient.Controllers
{
  [TypeFilter(typeof(InjectAppSettingsFilterAttribute))]
  public class ControllerBase : Controller
  {    
  }
}
