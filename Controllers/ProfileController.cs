using System.Globalization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RecoverPH_API.Models;

namespace RecoverPH_API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize] // requires authenticated user
    public class ProfileController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public ProfileController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        // GET api/profile
        [HttpGet]
        public async Task<IActionResult> GetProfile()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();

            return Ok(new
            {
                user.Id,
                user.UserName,
                user.Email,
                user.FullName,
                user.DisplayName,
                PhoneNumber = user.PhoneNumber,
                BirthDate = user.BirthDate.ToString("yyyy-MM-dd"),
                user.Gender,
                user.IsProfileComplete
            });
        }

        // POST api/profile/setup
        [HttpPost("setup")]
        public async Task<IActionResult> SetupProfile([FromBody] ProfileSetupDto dto)
        {
            if (dto == null) return BadRequest("No data supplied.");

            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();

            // Basic server-side validation (adjust as needed)
            var errors = new List<string>();
            if (string.IsNullOrWhiteSpace(dto.FullName)) errors.Add("FullName is required.");
            if (string.IsNullOrWhiteSpace(dto.DisplayName)) errors.Add("DisplayName is required.");
            if (!string.IsNullOrWhiteSpace(dto.BirthDate))
            {
                if (!DateOnly.TryParseExact(dto.BirthDate, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsedDate))
                {
                    // fallback: try Parse
                    if (!DateOnly.TryParse(dto.BirthDate, out parsedDate))
                    {
                        errors.Add("BirthDate must be in yyyy-MM-dd format.");
                    }
                    else
                    {
                        user.BirthDate = parsedDate;
                    }
                }
                else
                {
                    user.BirthDate = parsedDate;
                }
            }

            if (errors.Count > 0)
                return BadRequest(new { errors });

            // Map DTO TO user
            user.FullName = dto.FullName?.Trim();
            user.DisplayName = dto.DisplayName?.Trim();
            if (!string.IsNullOrWhiteSpace(dto.PhoneNumber))
                user.PhoneNumber = dto.PhoneNumber.Trim();

            if (!string.IsNullOrWhiteSpace(dto.Gender))
                user.Gender = dto.Gender.Trim();

            user.IsProfileComplete = true;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                // return Identity errors in a friendly shape
                return BadRequest(new
                {
                    errors = result.Errors.Select(e => e.Description).ToArray()
                });
            }

            return Ok(new
            {
                message = "Profile updated",
                isProfileComplete = user.IsProfileComplete
            });
        }
    }

    // Simple DTO for profile setup
    public class ProfileSetupDto
    {
        public string? FullName { get; set; } = string.Empty;
        public string? DisplayName { get; set; } = string.Empty;

        // expect "yyyy-MM-dd" string format; server will validate/parse
        public string? PhoneNumber { get; set; } = string.Empty;
        public string? BirthDate { get; set; } = string.Empty;
        public string? Gender { get; set; } = string.Empty;
    }
}
