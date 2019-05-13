using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation;
using System.Collections.Generic;

namespace OAuthWebApp.Controllers
{
    [Authorize(AuthenticationSchemes = OpenIddictValidationDefaults.AuthenticationScheme)]
    [ApiController]
    [Route("api/[controller]")]
    public class SampleController : ControllerBase
    {
        [HttpGet]
        public List<string> Get()
        {
            return new List<string>
            {
                "This",
                "is",
                "a",
                "test"
            };
        }
    }
}