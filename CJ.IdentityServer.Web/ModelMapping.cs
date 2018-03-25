using AutoMapper;
using CJ.IdentityServer.ServiceModels.Login;
using CJ.IdentityServer.ServiceModels.User;
using CJ.IdentityServer.Services.Models;
using CJ.IdentityServer.Web.ViewModels.AccountViewModels;
using CJ.IdentityServer.Web.ViewModels.ManageViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Web
{
  public class MappingProfile : Profile
  {
    public MappingProfile()
    {
      CreateMap<ApplicationUser, ManageVM>()
        .ForMember(x => x.Username, a => a.MapFrom(b => b.UserName))
        .ForMember(x => x.IsEmailConfirmed, a => a.MapFrom(b => b.EmailConfirmed))
        .ForMember(x => x.UserType, a => a.MapFrom(b => ((UserType)b.UserType)));


      //CreateMap<RegisterVM, ApplicationUser>()
      //  .ForMember(x => x.UserName, a => a.MapFrom(b => b.Email));

      CreateMap<RegisterVM, UserSM>();

      CreateMap<LoginInputVM, LoginSM>();
    }
  }
}
