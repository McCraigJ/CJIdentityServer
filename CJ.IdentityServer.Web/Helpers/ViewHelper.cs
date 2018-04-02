using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace CJ.IdentityServer.Web.Helpers
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
