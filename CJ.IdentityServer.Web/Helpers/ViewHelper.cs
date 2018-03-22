using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Helpers
{
  public static class ViewHelper
  {
    public static string GetUserName(IEnumerable<Claim> claims)
    {
      return claims.FirstOrDefault(x => x.Type == "name")?.Value;
    }

    public static string GetIdentityProvider(IEnumerable<Claim> claims)
    {
      return claims.FirstOrDefault(x => x.Type == "idp")?.Value;
    }
  }
}
