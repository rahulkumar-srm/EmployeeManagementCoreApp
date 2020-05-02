using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace EmployeeManagementCoreApp.ViewModels
{
    public class LoginWith2faViewModel
    {
        public bool RememberMe { get; set; }

        public string ReturnUrl { get; set; }

        public string TwoFactorCode { get; set; }

        public bool RememberMachine { get; set; }
    }
}
