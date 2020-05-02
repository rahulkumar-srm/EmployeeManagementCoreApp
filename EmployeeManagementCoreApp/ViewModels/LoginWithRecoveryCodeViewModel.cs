using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EmployeeManagementCoreApp.ViewModels
{
    public class LoginWithRecoveryCodeViewModel
    {
        public string ReturnUrl { get; set; }

        public string RecoveryCode { get; set; }
    }
}
