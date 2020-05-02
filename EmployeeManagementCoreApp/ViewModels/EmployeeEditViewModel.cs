﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace EmployeeManagementCoreApp.ViewModels
{
    public class EmployeeEditViewModel : EmployeeCreateViewModel
    {
        [Required]
        public int Id { get; set; }
        public string ExistingPhotoPath { get; set; }
    }
}
