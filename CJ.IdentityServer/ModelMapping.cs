using AutoMapper;
using CJ.IdentityServer.Models;
using CJ.IdentityServer.ViewModels.AccountViewModels;
using CJ.IdentityServer.ViewModels.ManageViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer
{
  public class MappingProfile : Profile
  {
    public MappingProfile()
    {
      CreateMap<ApplicationUser, ManageVM>()
        .ForMember(x => x.Username, a => a.MapFrom(b => b.UserName))
        .ForMember(x => x.IsEmailConfirmed, a => a.MapFrom(b => b.EmailConfirmed))
        .ForMember(x => x.UserType, a => a.MapFrom(b => ((UserType)b.UserType).ToString()));

      CreateMap<RegisterVM, ApplicationUser>()
        .ForMember(x => x.UserName, a => a.MapFrom(b => b.Email));        
    }
  }
}
