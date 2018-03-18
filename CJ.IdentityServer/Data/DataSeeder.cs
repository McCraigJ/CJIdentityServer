using CJ.IdentityServer.Models;
using CJ.IdentityServer.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Data
{
  public class DataSeeder
  {
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private IConfigurationSection _appSettings;

    public DataSeeder(
      UserManager<ApplicationUser> userManager,
      RoleManager<IdentityRole> roleManager,
      IConfiguration configuration)
    {
      _userManager = userManager;
      _roleManager = roleManager;
      _appSettings = configuration.GetSection("AppSettings");
    }

    public async void CreateDefaultData()
    {
      if (Convert.ToBoolean(_appSettings["SeedData"]) == true)
      {
        // Seed roles
        if (!_roleManager.Roles.Any())
        {
          var roles = Enum.GetValues(typeof(UserRoles));
          foreach (var r in roles)
          {
            var result = await _roleManager.CreateAsync(new IdentityRole { Name = r.ToString() });
          }
        }

        // Seed default user
        if (!_userManager.Users.Any())
        {
          var user = new ApplicationUser
          {
            UserName = "admin"
          };
          var resultUser = await _userManager.CreateAsync(user, "_Install123");
          if (resultUser.Succeeded)
          {
            var resultAddToRole = await _userManager.AddToRoleAsync(user, UserRoles.SystemAdmin.ToString());
          }
        }
      }
    }

  }
}
