using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CJ.MvcClient
{
  public class Startup
  {
    private IConfigurationSection _appSettings;
    public Startup(IConfiguration configuration)
    {
      Configuration = configuration;
      _appSettings = configuration.GetSection("AppSettings");
    }

    public IConfiguration Configuration { get; }

    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services)
    {
      services.AddMvc();

      JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

      services.AddAuthentication(options =>
      {
        options.DefaultScheme = "Cookies";
        options.DefaultChallengeScheme = "oidc";
      })
          .AddCookie("Cookies")
          .AddOpenIdConnect("oidc", options =>
          {
            options.SignInScheme = "Cookies";

            options.Authority = _appSettings["IdentityServerAuthority"]; // "http://localhost:5000";
            options.RequireHttpsMetadata = false;
            options.ResponseType = "code id_token";
            options.GetClaimsFromUserInfoEndpoint = true;
            options.SaveTokens = true;

            options.ClientId = "mvc";
            options.ClientSecret = "secret";                    
          });
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IHostingEnvironment env)
    {
      if (env.IsDevelopment())
      {
        app.UseBrowserLink();
        app.UseDeveloperExceptionPage();
      }
      else
      {
        app.UseExceptionHandler("/Home/Error");
      }

      app.UseAuthentication();

      app.UseStaticFiles();

      app.UseMvc(routes =>
      {
        routes.MapRoute(
                  name: "default",
                  template: "{controller=Home}/{action=Index}/{id?}");
      });
    }
  }
}
