using AutoMapper;
using CJ.IdentityServer.ServiceModels.Client;
using CJ.IdentityServer.ServiceModels.Identity;
using CJ.IdentityServer.ServiceModels.Login;
using CJ.IdentityServer.ServiceModels.User;
using CJ.IdentityServer.Services.Models;
using IdentityServer4.Models;

namespace CJ.IdentityServer.Services
{
  public class MappingProfile : Profile
  {
    public MappingProfile()
    {
      CreateMap<ApplicationUser, UserSM>().ReverseMap();
      CreateMap<LogoutRequest, LogoutResultSM>();
      CreateMap<AuthorizationRequest, AuthorisationRequestSM>();
      CreateMap<Client, ClientSM>();

      CreateMap<Secret, SecretSM>();
      CreateMap<Scope, ScopeSM>();

      CreateMap<IdentityResource, IdentityResourceSM>();
      CreateMap<ApiResource, ApiResourceSM>();
      CreateMap<Resources, SecurableResourcesSM>();

      CreateMap<AuthorisationRequestSM, AuthorizationRequest>();
      CreateMap<ConsentResponseSM, ConsentResponse>();      

    }
  }
}
