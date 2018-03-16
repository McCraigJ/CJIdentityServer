using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace CJ.IdentityServer
{
  public class Program
  {
    public static void Main(string[] args)
    {
      BuildWebHost(args).Run();
    }

    public static IWebHost BuildWebHost(string[] args) => BuildWebHost(args, true);
        //WebHost.CreateDefaultBuilder(args)
        //    .UseStartup<Startup>()
        //    .Build();

    private static IWebHost BuildWebHost(string[] args, bool useDefaultBuilder)
    {
      if (useDefaultBuilder)
      {
        return WebHost.CreateDefaultBuilder(args)
           .UseStartup<Startup>()
           .Build();
      } else
      {
        return new WebHostBuilder()
          .UseKestrel()
          .UseUrls("http://localhost:5000")
          .UseContentRoot(Directory.GetCurrentDirectory())
          .UseIISIntegration()
          .UseStartup<Startup>()
          .Build();

      }
    }
  }
}
