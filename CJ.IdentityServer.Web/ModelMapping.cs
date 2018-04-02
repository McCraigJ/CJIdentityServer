using AutoMapper;
using CJ.IdentityServer.ServiceModels.Login;
using CJ.IdentityServer.ServiceModels.User;
using CJ.IdentityServer.Web.ViewModels.AccountViewModels;
using CJ.IdentityServer.Web.ViewModels.ManageViewModels;

namespace CJ.IdentityServer.Web
{
  public class MappingProfile : Profile
  {
    public MappingProfile()
    {
      //CreateMap<ApplicationUser, ManageVM>()
      //  .ForMember(x => x.Username, a => a.MapFrom(b => b.UserName))
      //  .ForMember(x => x.IsEmailConfirmed, a => a.MapFrom(b => b.EmailConfirmed))
      //  .ForMember(x => x.UserType, a => a.MapFrom(b => ((UserType)b.UserType)));




      //CreateMap<RegisterVM, ApplicationUser>()
      //  .ForMember(x => x.UserName, a => a.MapFrom(b => b.Email));

      CreateMap<UserSM, ManageVM>()
        .ForMember(x => x.UserType, a => a.MapFrom(b => ((UserType)b.UserType).ToString()))
        .ReverseMap();

      CreateMap<RegisterVM, UserSM>();

      CreateMap<LoginInputVM, LoginSM>();
    }
  }
}
