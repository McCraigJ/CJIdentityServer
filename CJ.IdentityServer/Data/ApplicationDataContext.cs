using CJ.IdentityServer.Data.DataModels;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Data
{
  public class ApplicationDataContext : DbContext
  {
    public ApplicationDataContext(DbContextOptions<ApplicationDataContext> options) : base(options)
    {
    }
    public DbSet<UserDM> Users { get; set; }
  }
}
