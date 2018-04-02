using CJ.IdentityServer.Interfaces;
using CJ.IdentityServer.ServiceModels.User;
using CJ.IdentityServer.Web.ViewModels.UsersViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Text.Encodings.Web;

namespace CJ.IdentityServer.Web.Controllers
{
  [Authorize(Roles = UserSM.SysAdminRoleName)]
  [Route("[controller]/[action]")]
  public class UsersController : ControllerBase
  {
    private readonly IAccountService _accountService;
    private readonly INotificationService _notificationService;
    private readonly ILogger _logger;
    private readonly UrlEncoder _urlEncoder;
       

    public UsersController(
      IAccountService accountService,            
      INotificationService notificationService,      
      ILogger<ManageController> logger,
      UrlEncoder urlEncoder
      )
    {
      _accountService = accountService;
      _notificationService = notificationService;
      _logger = logger;
      _urlEncoder = urlEncoder;
    }    

    [HttpGet]
    public IActionResult Index()
    {
      var users = _accountService.GetAllUsers();
      return View(new UsersVM { Users = users });            
    }


    //[HttpGet]

    
  }
}
