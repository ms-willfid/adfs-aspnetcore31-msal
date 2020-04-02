using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

using SampleApp.Models;
using SampleApp.Services;

namespace SampleApp.Controllers
{

    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IMsalService _msalClient;

        public HomeController(ILogger<HomeController> logger, IMsalService msalClient)
        {
            this._logger = logger;
            this._msalClient = msalClient;
        }

        public IActionResult Index()
        {
            var token = _msalClient.GetToken("api://api.contosocloud.xyz/5c0d2259-c196-42c5-afd4-3ce2d3a01ea2/read");
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [AllowAnonymous]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
