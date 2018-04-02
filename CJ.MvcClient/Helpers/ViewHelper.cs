using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace CJ.MvcClient.Helpers
{
  public static class ViewHelper
  {
    public static string GetFirstOrUserName(IEnumerable<Claim> claims)
    {
      var firstName = claims.FirstOrDefault(x => x.Type == "firstname")?.Value;
      if (string.IsNullOrEmpty(firstName))
      {
        return claims.FirstOrDefault(x => x.Type == "name")?.Value;
      }
      return firstName;
    }

    public static bool IsAdmin(IEnumerable<Claim> claims)
    {
      return claims.FirstOrDefault(x => x.Type == "admin")?.Value == "True";
    }
  }
}
