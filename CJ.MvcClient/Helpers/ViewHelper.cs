using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace CJ.MvcClient.Helpers
{
  public static class ViewHelper
  {
    public static string GetUserName(IEnumerable<Claim> claims)
    {
      return claims.FirstOrDefault(x => x.Type == "name")?.Value;
    }
  }
}
