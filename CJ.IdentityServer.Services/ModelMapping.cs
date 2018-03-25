using AutoMapper;
using CJ.IdentityServer.ServiceModels.Login;
using CJ.IdentityServer.ServiceModels.User;
using CJ.IdentityServer.Services.Models;
using IdentityServer4.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace CJ.IdentityServer.Services
{
  public class MappingProfile : Profile
  {
    public MappingProfile()
    {
      CreateMap<ApplicationUser, UserSM>().ReverseMap();
      CreateMap<LogoutRequest, LogoutResultSM>();
    }
  }
}
