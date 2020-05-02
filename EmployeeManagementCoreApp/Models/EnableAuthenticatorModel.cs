using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EmployeeManagementCoreApp.Models
{
    public class EnableAuthenticatorModel
    {
        [TempData]
        public string StatusMessage { get; set; }

        public string Code { get; set; }
    }
}
