using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CJ.IdentityServer.Web.ViewModels
{
  public class CheckBoxListItemVM
  {
    public string Id { get; set; }
    public string DisplayName { get; set; }
    public bool IsChecked { get; set; }
  }
}
