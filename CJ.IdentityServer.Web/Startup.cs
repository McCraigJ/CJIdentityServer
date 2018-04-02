using AutoMapper;
using CJ.Common.EmailNotification;
using CJ.Common.Interfaces;
using CJ.IdentityServer.Interfaces;
using CJ.IdentityServer.Services.Account;
using CJ.IdentityServer.Services.Data;
using CJ.IdentityServer.Services.Identity;
using CJ.IdentityServer.Services.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CJ.IdentityServer.Web
{
  public class Startup
  {

    private IConfigurationSection _appSettings;
    private IConfiguration _configuration { get; }

    public Startup(IConfiguration configuration)
    {
      _configuration = configuration;
      _appSettings = configuration.GetSection("AppSettings");
    }

    // This method gets called by the runtime. Use this method to add services to the container.
    // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
    public void ConfigureServices(IServiceCollection services)
    {
      services.AddDbContext<ApplicationDbContext>(options =>
          options.UseSqlServer(_configuration.GetConnectionString("DefaultConnection")));

      services.AddIdentity<ApplicationUser, IdentityRole>()
          .AddEntityFrameworkStores<ApplicationDbContext>()
          .AddDefaultTokenProviders();

      
      services.AddTransient<INotificationService, NotificationService>();
      services.AddTransient<INotifierService, EmailNotifierService>();
      
      services.AddMvc();
      services.AddAutoMapper();

      services.AddIdentityServer()
        .AddDeveloperSigningCredential()
        .AddInMemoryPersistedGrants()
        //.AddInMemoryApiResources(Config.GetApiResources())
        .AddInMemoryIdentityResources(Config.GetIdentityResources())
        .AddInMemoryClients(Config.GetClients(_appSettings))
        .AddAspNetIdentity<ApplicationUser>();

      services.AddTransient<IAccountService, AccountService>();
      services.AddTransient<ISecurableService, SecurableService>();

      services.AddTransient<IProfileService, ProfileService>();

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
