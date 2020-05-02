using EmployeeManagementCoreApp.Models;
using EmployeeManagementCoreApp.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EmployeeManagementCoreApp.Controllers
{ 
    public class ErrorController : Controller
    {
        [Route("Error/{statusCode}")]
        public IActionResult HttpStatusCodeHandler(int statusCode)
        {
            switch (statusCode)
            {
                case 404:
                    ViewBag.ErrorMessage = "Sorry, the resource you requested could not be found";
                    break;
            }

            return View("NotFound");
        }

        [AllowAnonymous]
        [Route("Error")]
        public IActionResult Error()
        {
            var exceptionHandlerPathFeature = HttpContext.Features.Get<IExceptionHandlerPathFeature>();
            ErrorViewModel errorViewModel = new ErrorViewModel
            {
                ExceptionPath = exceptionHandlerPathFeature.Path,
                ExceptionMessage = exceptionHandlerPathFeature.Error.Message,
                StackTrace = exceptionHandlerPathFeature.Error.StackTrace
            };
            return View(errorViewModel);
        }
    }

}
