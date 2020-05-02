using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace EmployeeManagementCoreApp.Models
{
    public class LoginWithRecoveryCodeModel
    {
        public string ReturnUrl { get; set; } = @"/";

        [Required]
        public string RecoveryCode { get; set; }
    }
}
