using CJ.IdentityServer.Interfaces;
using CJ.IdentityServer.ServiceModels.User;
using CJ.IdentityServer.Web.ViewModels;
using CJ.IdentityServer.Web.ViewModels.UsersViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

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
      return View(new UsersVM { Users = users, StatusMessage = StatusMessage });            
    }


    //[Route("{id}")]
    [HttpGet]
    public async Task<IActionResult> UpdateRole(string id)
    {
      var user = await _accountService.FindUserByIdAsync(id);
      if (user == null)
      {
        throw new Exception("Unknown userid");
      }
      var rolesForUser = await _accountService.GetRolesForUserAsync(user);

      var model = PopulateUserRolesViewModel(user, rolesForUser);      

      return View(model);

    }
    
    [ValidateAntiForgeryToken]
    [HttpPost]
    public async Task<IActionResult> UpdateRole(UserRolesVM model)
    {
      if (ModelState.IsValid)
      {

        if (User.Claims.FirstOrDefault(x => x.Type == "sub")?.Value == model.Id)
        {
          StatusMessage = "Cannot update the logged-in user's role";
          return RedirectToAction("Index");
        }

          var addToRoles = new List<string>();
        var removeFromRoles = new List<string>();
        foreach (var r in model.UserRoles)
        {                   
          if (r.IsChecked)
          {
            addToRoles.Add(r.Id);
          } else
          {
            removeFromRoles.Add(r.Id);
          }
          
        }
        await _accountService.UpdateUserRolesAsync(model.Id, addToRoles, removeFromRoles);

        StatusMessage = "User Roles Updated for " + model.UserName;
        return RedirectToAction("Index");
      }

      var user = await _accountService.FindUserByIdAsync(model.Id);

      var rolesForUser = await _accountService.GetRolesForUserAsync(user);

      var m = PopulateUserRolesViewModel(user, rolesForUser);      

      return View("UpdateRole", m);
    }

    private UserRolesVM PopulateUserRolesViewModel(UserSM user, IEnumerable<string> rolesForUser)
    {      
      var model = new UserRolesVM();
      model.Id = user.Id;
      model.UserName = user.UserName;
      model.Name = user.FirstName + " " + user.LastName;
      model.Email = user.Email;
      model.UserRoles = Enum.GetValues(typeof(UserRole)).Cast<UserRole>().Select(x => new CheckBoxListItemVM
      {
        Id = x.ToString(),
        DisplayName = x.ToString()
      }).ToList();

      model.UserRoles.ForEach(x => x.IsChecked = rolesForUser.Contains(x.Id));

      return model;
    }

  }
}
