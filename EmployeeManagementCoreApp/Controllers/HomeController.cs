using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using EmployeeManagementCoreApp.Models;
using EmployeeManagementCoreApp.Models.Interfaces;
using Microsoft.AspNetCore.Hosting;
using System.IO;
using Microsoft.AspNetCore.Authorization;
using EmployeeManagementCoreApp.ViewModels;
using Microsoft.AspNetCore.DataProtection;
using EmployeeManagementCoreApp.Security;

namespace EmployeeManagementCoreApp.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IEmployeeRepository _employeeRepository;
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly IDataProtector _protector;

        public HomeController(ILogger<HomeController> logger, 
            IEmployeeRepository employeeRepository, 
            IWebHostEnvironment webHostEnvironment,
            IDataProtectionProvider dataProtectionProvider,
            DataProtectionPurposeStrings dataProtectionPurposeStrings)
        {
            _logger = logger;
            _employeeRepository = employeeRepository;
            _webHostEnvironment = webHostEnvironment;
            _protector = dataProtectionProvider.CreateProtector(dataProtectionPurposeStrings.EmployeeIdRouteValue);
        }

        public ViewResult Index()
        {
            List<Employee> model = _employeeRepository.GetAllEmployee().Select(e =>
            {
                e.EncryptedId = _protector.Protect(e.Id.ToString());
                return e;
            }).ToList();

            return View(model);
        }

        public ViewResult Details(string id)
        {
            string decryptedId = _protector.Unprotect(id);
            int decryptedIntId = Convert.ToInt32(decryptedId);

            Employee employee = _employeeRepository.GetEmployee(decryptedIntId);
            if(employee == null)
            {
                Response.StatusCode = 404;
                return View("EmployeeNotFound", id);
            }

            return View(employee);
        }

        [HttpGet]
        public ViewResult Create()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Create(EmployeeCreateViewModel employeeCreateViewModel)
        {
            if (ModelState.IsValid)
            {
                string uniqueFileName = ProcessUploadedFile(employeeCreateViewModel);

                Employee newEmployee = new Employee
                {
                    Name = employeeCreateViewModel.Name,
                    Email = employeeCreateViewModel.Email,
                    Department = employeeCreateViewModel.Department,
                    PhotoPath = uniqueFileName
                };

                _employeeRepository.Add(newEmployee);
                return RedirectToAction("details", new { id = newEmployee.Id });
            }

            return View();
        }

        private string ProcessUploadedFile(EmployeeCreateViewModel employeeCreateViewModel)
        {
            string uniqueFileName = null;

            if (employeeCreateViewModel.Photo != null)
            {
                string uploadsFolder = Path.Combine(_webHostEnvironment.WebRootPath, "images");
                uniqueFileName = Guid.NewGuid().ToString() + "_" + employeeCreateViewModel.Photo.FileName;
                string filePath = Path.Combine(uploadsFolder, uniqueFileName);
                using var fileStream = new FileStream(filePath, FileMode.Create);
                employeeCreateViewModel.Photo.CopyTo(fileStream);
            }

            return uniqueFileName;
        }

        [HttpGet]
        public ViewResult Edit(int id)
        {
            Employee employee = _employeeRepository.GetEmployee(id);
            if (employee == null)
            {
                Response.StatusCode = 404;
                return View("EmployeeNotFound", id);
            }
            EmployeeEditViewModel employeeEditViewModel = new EmployeeEditViewModel
            {
                Id = employee.Id,
                Name = employee.Name,
                Email = employee.Email,
                Department = employee.Department,
                ExistingPhotoPath = employee.PhotoPath
            };
            return View(employeeEditViewModel);
        }

        [HttpPost]
        public IActionResult Edit(EmployeeEditViewModel model)
        {
            if (ModelState.IsValid)
            {
                Employee employee = _employeeRepository.GetEmployee(model.Id);
                employee.Name = model.Name;
                employee.Email = model.Email;
                employee.Department = model.Department;

                if (model.Photo != null)
                {
                    if (model.ExistingPhotoPath != null)
                    {
                        string filePath = Path.Combine(_webHostEnvironment.WebRootPath,
                            "images", model.ExistingPhotoPath);
                        System.IO.File.Delete(filePath);
                    }
                    employee.PhotoPath = ProcessUploadedFile(model);
                }

                _employeeRepository.Update(employee);

                return RedirectToAction("index");
            }

            return View(model);
        }

        public IActionResult Delete(int id)
        {
            _employeeRepository.Delete(id);
            return RedirectToAction("Index");
        }

        public IActionResult Privacy()
        {
            return View();
        }

        //[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        //public IActionResult Error()
        //{
        //    return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        //}
    }
}
