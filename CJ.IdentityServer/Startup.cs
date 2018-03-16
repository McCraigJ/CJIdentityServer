using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CJ.IdentityServer.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CJ.IdentityServer
{
  public class Startup
  {

    private IConfigurationSection _appSettings;

    public Startup(IConfiguration configuration)
    {       
      _appSettings = configuration.GetSection("AppSettings");
    }

    // This method gets called by the runtime. Use this method to add services to the container.
    // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
    public void ConfigureServices(IServiceCollection services)
    {      

      services.AddMvc();

      services.AddIdentityServer()
        .AddDeveloperSigningCredential()
        //.AddInMemoryApiResources(Config.GetApiResources())
        .AddInMemoryIdentityResources(Config.GetIdentityResources())
        .AddInMemoryClients(Config.GetClients(_appSettings));
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IHostingEnvironment env)
    {
      if (env.IsDevelopment())
      {
        app.UseDeveloperExceptionPage();
      }

      app.UseIdentityServer();

      app.UseStaticFiles();
      app.UseMvcWithDefaultRoute();
    }
  }
}
