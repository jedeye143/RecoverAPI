using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using RecoverPH_API.Models;
using RecoverPH_API.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Net;
using System.Net.Mail;
using System.Text.RegularExpressions;
using System.ComponentModel.DataAnnotations;

namespace RecoverPH_API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _config;
        private readonly PaymentService _paymentService;
        private readonly ILogger<AuthController> _logger;
        
        // Security: Rate limiting for external login attempts
        private static readonly Dictionary<string, List<DateTime>> _externalLoginAttempts = new();
        private static readonly object _rateLimitLock = new object();
        private const int MAX_EXTERNAL_LOGIN_ATTEMPTS = 5;
        private const int RATE_LIMIT_WINDOW_MINUTES = 15;
        
        // Security: Allowed email domains for external providers
        private static readonly HashSet<string> _allowedEmailDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", 
            "yahoo.com", "facebook.local" // For Facebook fallback emails
        };

        public AuthController(UserManager<ApplicationUser> userManager, IConfiguration config, PaymentService paymentService, ILogger<AuthController> logger)
        {
            _userManager = userManager;
            _config = config;
            _paymentService = paymentService;
            _logger = logger;
        }

        // LOGIN
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return Unauthorized(new { message = "Invalid username or password" });

            try
            {
                // Get subscription information from PaymentService
                var paymentSummary = await _paymentService.GetUserPaymentSummaryAsync(user.Id);
                var currentSubscription = paymentSummary.CurrentSubscription;
                var hasUsedFreeTrial = paymentSummary.HasUsedFreeTrial;
                var hasActiveSubscription = paymentSummary.HasActiveSubscription;

                // Note: Free trial is no longer automatically created on login
                // Users must explicitly choose to start a free trial

                // --- Claims ---
                var subscriptionPlan = currentSubscription != null 
                    ? $"{currentSubscription.PlanType}/{currentSubscription.BillingCycle}" 
                    : "Free/None";

                var claims = new List<Claim>
                {
                    new(JwtRegisteredClaimNames.Sub, user.Id),
                    new(JwtRegisteredClaimNames.UniqueName, user.UserName!),
                    new(JwtRegisteredClaimNames.Email, user.Email ?? ""),
                    new("displayName", user.DisplayName ?? ""),
                    new("subscriptionPlan", subscriptionPlan),
                    new("subscriptionActive", hasActiveSubscription.ToString())
                };

                var roles = await _userManager.GetRolesAsync(user);
                claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:SigningKey"]!));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(
                    issuer: _config["JWT:Issuer"],
                    audience: _config["JWT:Audience"],
                    claims: claims,
                    expires: DateTime.UtcNow.AddHours(1),
                    signingCredentials: creds
                );

                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

                // --- Next step logic ---
                string nextStep;
                if (!user.IsProfileComplete)
                {
                    nextStep = "profileSetup";
                }
                else if (!hasActiveSubscription)
                {
                    nextStep = "payment";
                }
                else
                {
                    nextStep = "dashboard";
                }

                return Ok(new
                {
                    tokenType = "Bearer",
                    token = tokenString,
                    expiresIn = 3600,
                    nextStep,
                    subscriptionPlan = subscriptionPlan,
                    subscriptionStart = currentSubscription?.StartDate,
                    subscriptionEnd = currentSubscription?.EndDate,
                    hasUsedFreeTrial = hasUsedFreeTrial
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error during login for user {user.UserName}");
                
                // Fallback response if PaymentService fails
                var claims = new List<Claim>
                {
                    new(JwtRegisteredClaimNames.Sub, user.Id),
                    new(JwtRegisteredClaimNames.UniqueName, user.UserName!),
                    new(JwtRegisteredClaimNames.Email, user.Email ?? ""),
                    new("displayName", user.DisplayName ?? ""),
                    new("subscriptionPlan", "Free/None"),
                    new("subscriptionActive", "false")
                };

                var roles = await _userManager.GetRolesAsync(user);
                claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:SigningKey"]!));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(
                    issuer: _config["JWT:Issuer"],
                    audience: _config["JWT:Audience"],
                    claims: claims,
                    expires: DateTime.UtcNow.AddHours(1),
                    signingCredentials: creds
                );

                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

                return Ok(new
                {
                    tokenType = "Bearer",
                    token = tokenString,
                    expiresIn = 3600,
                    nextStep = user.IsProfileComplete ? "payment" : "profileSetup",
                    subscriptionPlan = "Free/None",
                    subscriptionStart = (DateTime?)null,
                    subscriptionEnd = (DateTime?)null,
                    hasUsedFreeTrial = false
                });
            }
        }

        // REGISTER + AUTO-LOGIN
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email,
                IsProfileComplete = false
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            // Auto-login after registration
            return await Login(new LoginDto
            {
                Username = model.Username,
                Password = model.Password
            });
        }

        public class RegisterDto
        {
            public string Username { get; set; } = string.Empty;
            public string Email { get; set; } = string.Empty;
            public string Password { get; set; } = string.Empty;
        }

        public class LoginDto
        {
            public string Username { get; set; } = string.Empty;
            public string Password { get; set; } = string.Empty;
        }

        // --- Forgot / Reset Password (Brevo SMTP) ---
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto dto)
        {
            if (dto == null || string.IsNullOrWhiteSpace(dto.Email))
                return BadRequest(new { message = "Email is required" });

            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
            {
                // Do not reveal user existence
                return Ok(new { message = "If the email exists, a reset link was sent." });
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            // Determine reset link host
            var frontendBase = !string.IsNullOrWhiteSpace(dto.ReturnBaseUrl)
                ? dto.ReturnBaseUrl
                : (_config["WebApp:BaseUrl"] ?? ($"{Request.Scheme}://{Request.Host}"));
            frontendBase = frontendBase.TrimEnd('/');
            var resetLink = $"{frontendBase}/Account/ResetPassword?email={WebUtility.UrlEncode(dto.Email)}&token={WebUtility.UrlEncode(token)}";

            var brevo = _config.GetSection("Email:Brevo");
            try
            {
                using var smtp = new SmtpClient(brevo.GetValue<string>("SmtpHost"), brevo.GetValue<int>("SmtpPort"));
                smtp.Credentials = new NetworkCredential(brevo.GetValue<string>("SmtpUsername"), brevo.GetValue<string>("SmtpPassword"));
                smtp.EnableSsl = brevo.GetValue<bool>("UseStartTls");

                using var mail = new MailMessage
                {
                    From = new MailAddress(brevo.GetValue<string>("FromEmail"), brevo.GetValue<string>("FromName")),
                    Subject = "RecoverPH - Password Reset",
                    Body = $"Click to reset your password: {resetLink}",
                    IsBodyHtml = false
                };
                mail.To.Add(dto.Email);
                await smtp.SendMailAsync(mail);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Failed to send reset email", detail = ex.Message });
            }

            return Ok(new { message = "Reset email sent if the account exists." });
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto dto)
        {
            if (dto == null || string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.Token) || string.IsNullOrWhiteSpace(dto.NewPassword))
                return BadRequest(new { message = "Email, token and newPassword are required" });

            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
                return BadRequest(new { message = "Invalid email" });

            // Normalize token: spaces occasionally replace '+' when emailed/opened
            var normalizedToken = (dto.Token ?? string.Empty).Replace(" ", "+");
            var result = await _userManager.ResetPasswordAsync(user, normalizedToken, dto.NewPassword);
            if (!result.Succeeded)
                return BadRequest(new { errors = result.Errors.Select(e => e.Description).ToArray() });

            return Ok(new { message = "Password has been reset successfully." });
        }

        public class ForgotPasswordDto
        {
            public string Email { get; set; } = string.Empty;
            public string? ReturnBaseUrl { get; set; }
        }

        public class ResetPasswordDto
        {
            public string Email { get; set; } = string.Empty;
            public string Token { get; set; } = string.Empty;
            public string NewPassword { get; set; } = string.Empty;
        }

        // --- External login (Google/Facebook) ---
        [HttpGet("external-login/{provider}")]
        public async Task<IActionResult> ExternalLogin([FromRoute] string provider, [FromQuery] string? returnUrl = null)
        {
            // Security: Rate limiting check
            var clientIp = GetClientIpAddress();
            if (IsRateLimited(clientIp))
            {
                _logger.LogWarning($"Rate limit exceeded for external login from IP: {clientIp}");
                return StatusCode(429, new { message = "Too many requests. Please try again later." });
            }

            var scheme = NormalizeExternalScheme(provider);
            if (scheme == null)
            {
                _logger.LogWarning($"Unsupported external login provider attempted: {provider} from IP: {clientIp}");
                return BadRequest(new { message = "Unsupported provider" });
            }

            // Security: Validate return URL to prevent open redirects
            if (!string.IsNullOrWhiteSpace(returnUrl) && !IsValidReturnUrl(returnUrl))
            {
                _logger.LogWarning($"Invalid return URL attempted: {returnUrl} from IP: {clientIp}. BaseUrl config: {_config["WebApp:BaseUrl"]}");
                return BadRequest(new { message = "Invalid return URL" });
            }

            // Security: Audit logging
            _logger.LogInformation($"External login initiated: Provider={scheme}, IP={clientIp}, ReturnUrl={returnUrl}");

            // Clear any stale external cookies that could break correlation
            await HttpContext.SignOutAsync("External");

            // Default return URL if not supplied
            if (string.IsNullOrWhiteSpace(returnUrl))
            {
                var baseUrl = _config["WebApp:BaseUrl"]?.TrimEnd('/') ?? $"{Request.Scheme}://{Request.Host}";
                returnUrl = $"{baseUrl}/Account/Login";
            }

            var redirectUrl = Url.ActionLink(nameof(ExternalLoginCallback), values: new { provider = scheme, returnUrl });
            var properties = new Microsoft.AspNetCore.Authentication.AuthenticationProperties { RedirectUri = redirectUrl };
            return Challenge(properties, scheme);
        }

        [HttpGet("external-login-callback/{provider}")]
        public async Task<IActionResult> ExternalLoginCallback([FromRoute] string provider, [FromQuery] string? returnUrl = null)
        {
            var clientIp = GetClientIpAddress();
            var scheme = NormalizeExternalScheme(provider);
            if (scheme == null)
            {
                _logger.LogWarning($"Unsupported external login callback provider: {provider} from IP: {clientIp}");
                return BadRequest(new { message = "Unsupported provider" });
            }

            var result = await Microsoft.AspNetCore.Authentication.AuthenticationHttpContextExtensions.AuthenticateAsync(HttpContext, scheme);
            if (!result.Succeeded)
            {
                _logger.LogWarning($"External authentication failed for provider: {scheme} from IP: {clientIp}");
                return BadRequest(new { message = "External authentication failed" });
            }

            // Security: Extract and validate email with enhanced security
            var externalEmail = ExtractEmailFromClaims(result.Principal);
            
            // Security: Validate email format and domain
            if (!IsValidEmail(externalEmail))
            {
                _logger.LogWarning($"Invalid email format from external provider: {scheme}, Email: {externalEmail}, IP: {clientIp}");
                return BadRequest(new { message = "Invalid email format" });
            }

            // Security: Check for account linking conflicts
            var existingUser = await _userManager.FindByEmailAsync(externalEmail);
            if (existingUser != null)
            {
                // Check if user was created with different external provider
                var existingProvider = await _userManager.GetAuthenticationTokenAsync(existingUser, "External", "Provider");
                if (!string.IsNullOrEmpty(existingProvider) && existingProvider != scheme)
                {
                    _logger.LogWarning($"Account linking conflict: Email {externalEmail} already linked to {existingProvider}, attempted {scheme} from IP: {clientIp}");
                    return BadRequest(new { message = "Account already exists with different provider" });
                }
            }

            var user = await _userManager.FindByEmailAsync(externalEmail);
            if (user == null)
            {
                // Security: Rate limiting for account creation
                if (IsRateLimited(clientIp))
                {
                    _logger.LogWarning($"Rate limit exceeded for account creation from IP: {clientIp}");
                    return StatusCode(429, new { message = "Too many requests. Please try again later." });
                }

                // Security: Create user with enhanced validation
                user = new ApplicationUser { UserName = externalEmail, Email = externalEmail, IsProfileComplete = false };
                var createRes = await _userManager.CreateAsync(user);
                if (!createRes.Succeeded)
                {
                    _logger.LogError($"Failed to create user for email: {externalEmail}, Errors: {string.Join(", ", createRes.Errors.Select(e => e.Description))}, IP: {clientIp}");
                    return BadRequest(new { message = "Failed to create user" }); // Security: Don't expose internal errors
                }

                // Security: Store external provider information
                await _userManager.SetAuthenticationTokenAsync(user, "External", "Provider", scheme);
                _logger.LogInformation($"New user created via external login: {externalEmail}, Provider: {scheme}, IP: {clientIp}");
            }

            // Security: Enrich and persist profile info from external claims
            try
            {
                await UpdateUserProfileFromClaimsAsync(user, result.Principal!);
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Failed to update user profile from external claims: {ex.Message}, User: {externalEmail}, IP: {clientIp}");
                // Continue to JWT issuance - non-fatal
            }

            // Security: Issue JWT with enhanced security
            try
            {
                var paymentSummary = await _paymentService.GetUserPaymentSummaryAsync(user.Id);
                var currentSubscription = paymentSummary.CurrentSubscription;
                var hasActiveSubscription = paymentSummary.HasActiveSubscription;
                var subscriptionPlan = currentSubscription != null ? $"{currentSubscription.PlanType}/{currentSubscription.BillingCycle}" : "Free/None";

                var claims = new List<Claim>
                {
                    new(JwtRegisteredClaimNames.Sub, user.Id),
                    new(JwtRegisteredClaimNames.UniqueName, user.UserName!),
                    new(JwtRegisteredClaimNames.Email, user.Email ?? ""),
                    new("displayName", user.DisplayName ?? ""),
                    new("subscriptionPlan", subscriptionPlan),
                    new("subscriptionActive", hasActiveSubscription.ToString()),
                    new("authMethod", "external"), // Security: Track authentication method
                    new("externalProvider", scheme) // Security: Track external provider
                };
                var roles = await _userManager.GetRolesAsync(user);
                claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:SigningKey"]!));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var token = new JwtSecurityToken(
                    issuer: _config["JWT:Issuer"],
                    audience: _config["JWT:Audience"],
                    claims: claims,
                    expires: DateTime.UtcNow.AddHours(1),
                    signingCredentials: creds
                );
                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

                var nextStep = user.IsProfileComplete ? (hasActiveSubscription ? "dashboard" : "payment") : "profileSetup";

                // Security: Audit successful login
                _logger.LogInformation($"External login successful: User={externalEmail}, Provider={scheme}, IP={clientIp}, NextStep={nextStep}");

                if (!string.IsNullOrWhiteSpace(returnUrl))
                {
                    // Security: Validate return URL again before redirect
                    if (!IsValidReturnUrl(returnUrl))
                    {
                        _logger.LogWarning($"Invalid return URL in callback: {returnUrl}, User: {externalEmail}, IP: {clientIp}");
                        returnUrl = $"{_config["WebApp:BaseUrl"]?.TrimEnd('/') ?? $"{Request.Scheme}://{Request.Host}"}/Account/Login";
                    }

                    // Append token using multiple common conventions to maximize frontend compatibility
                    var separator = returnUrl.Contains('?') ? '&' : '?';
                    var query = $"token={WebUtility.UrlEncode(tokenString)}&tokenType=Bearer&nextStep={WebUtility.UrlEncode(nextStep)}&access_token={WebUtility.UrlEncode(tokenString)}&token_type=Bearer&expires_in=3600";
                    var urlWithQuery = $"{returnUrl}{separator}{query}";
                    // Also add as URL fragment for SPAs reading from hash
                    var redirect = urlWithQuery + $"#access_token={WebUtility.UrlEncode(tokenString)}&token_type=Bearer&expires_in=3600&nextStep={WebUtility.UrlEncode(nextStep)}";
                    return Redirect(redirect);
                }

                return Ok(new { tokenType = "Bearer", token = tokenString, expiresIn = 3600, nextStep });
            }
            catch (Exception ex)
            {
                _logger.LogError($"JWT generation failed for external login: {ex.Message}, User: {externalEmail}, IP: {clientIp}");
                return Ok(new { tokenType = "Bearer", token = string.Empty, expiresIn = 0, nextStep = "payment" });
            }
        }

        // Google default callback path support (maps to the same external callback logic)
        [AllowAnonymous]
        [HttpGet("/signin-google")]
        public Task<IActionResult> GoogleSigninCallback([FromQuery] string? returnUrl = null)
        {
            if (string.IsNullOrWhiteSpace(returnUrl))
            {
                var baseUrl = _config["WebApp:BaseUrl"]?.TrimEnd('/') ?? $"{Request.Scheme}://{Request.Host}";
                returnUrl = $"{baseUrl}/Account/Login";
            }
            return ExternalLoginCallback("google", returnUrl);
        }

        // Facebook default callback path support
        [AllowAnonymous]
        [HttpGet("/signin-facebook")]
        public Task<IActionResult> FacebookSigninCallback([FromQuery] string? returnUrl = null)
        {
            if (string.IsNullOrWhiteSpace(returnUrl))
            {
                var baseUrl = _config["WebApp:BaseUrl"]?.TrimEnd('/') ?? $"{Request.Scheme}://{Request.Host}";
                returnUrl = $"{baseUrl}/Account/Login";
            }
            return ExternalLoginCallback("facebook", returnUrl);
        }

        private static string? NormalizeExternalScheme(string provider)
        {
            if (string.IsNullOrWhiteSpace(provider)) return null;
            var p = provider.Trim();
            if (string.Equals(p, "google", StringComparison.OrdinalIgnoreCase)) return "Google";
            if (string.Equals(p, "facebook", StringComparison.OrdinalIgnoreCase)) return "Facebook";
            return null;
        }

        private async Task UpdateUserProfileFromClaimsAsync(ApplicationUser user, ClaimsPrincipal principal)
        {
            string? GetClaim(params string[] types)
            {
                foreach (var t in types)
                {
                    var v = principal.FindFirstValue(t);
                    if (!string.IsNullOrWhiteSpace(v)) return v;
                }
                return null;
            }

            // We intentionally do NOT set FullName/DisplayName here.
            // Those fields are collected and saved via Complete Profile flow.
            var phone = GetClaim(ClaimTypes.MobilePhone, ClaimTypes.HomePhone, ClaimTypes.OtherPhone, "phone_number");
            var gender = GetClaim(ClaimTypes.Gender, "gender");
            var birthdateStr = GetClaim(ClaimTypes.DateOfBirth, "birthdate");

            // Update only when empty or when coming from external for first time
            bool changed = false;
            if (!string.IsNullOrWhiteSpace(phone) && string.IsNullOrWhiteSpace(user.PhoneNumber)) { user.PhoneNumber = phone; changed = true; }
            if (!string.IsNullOrWhiteSpace(gender) && string.IsNullOrWhiteSpace(user.Gender)) { user.Gender = gender; changed = true; }

            if (!string.IsNullOrWhiteSpace(birthdateStr))
            {
                if (DateTime.TryParse(birthdateStr, out var dobDt))
                {
                    var dob = DateOnly.FromDateTime(dobDt);
                    if (user.BirthDate == default) { user.BirthDate = dob; changed = true; }
                }
            }

            if (changed)
            {
                await _userManager.UpdateAsync(user);
            }
        }

        // ===== SECURITY HELPER METHODS =====

        /// <summary>
        /// Security: Extract email from external provider claims with enhanced validation
        /// </summary>
        private string ExtractEmailFromClaims(ClaimsPrincipal? principal)
        {
            if (principal == null) return string.Empty;

            // Try multiple email claim types for different providers
            var emailClaimTypes = new[]
            {
                ClaimTypes.Email,
                "email",
                "emailaddress",
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/email"
            };

            var email = emailClaimTypes
                .Select(type => principal.FindFirstValue(type))
                .FirstOrDefault(e => !string.IsNullOrWhiteSpace(e));

            if (!string.IsNullOrWhiteSpace(email))
                return email.Trim().ToLowerInvariant();

            // For Facebook, if no email, try to get it from the name identifier or create a fallback
            var nameIdentifier = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            var name = principal.FindFirstValue(ClaimTypes.Name);
            
            if (!string.IsNullOrWhiteSpace(nameIdentifier))
            {
                // Create a fallback email using Facebook ID
                return $"fb_{nameIdentifier}@facebook.local";
            }
            else if (!string.IsNullOrWhiteSpace(name))
            {
                // Use name as fallback
                return $"{name.Replace(" ", ".").ToLower()}@facebook.local";
            }

            return string.Empty;
        }

        /// <summary>
        /// Security: Validate email format and domain
        /// </summary>
        private bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            // Basic email format validation
            var emailRegex = new Regex(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$");
            if (!emailRegex.IsMatch(email))
                return false;

            // Extract domain
            var domain = email.Split('@')[1].ToLowerInvariant();
            
            // Allow Facebook fallback emails
            if (domain == "facebook.local")
                return true;

            // Check against allowed domains
            return _allowedEmailDomains.Contains(domain);
        }

        /// <summary>
        /// Security: Validate return URL to prevent open redirects
        /// </summary>
        private bool IsValidReturnUrl(string returnUrl)
        {
            if (string.IsNullOrWhiteSpace(returnUrl))
                return false;

            try
            {
                var uri = new Uri(returnUrl, UriKind.Absolute);
                var baseUrl = _config["WebApp:BaseUrl"]?.TrimEnd('/');
                
                // Security: Block dangerous schemes
                if (uri.Scheme != "http" && uri.Scheme != "https")
                    return false;
                
                // Security: Block javascript: and data: schemes
                if (returnUrl.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase) ||
                    returnUrl.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
                    return false;
                
                if (!string.IsNullOrEmpty(baseUrl))
                {
                    var baseUri = new Uri(baseUrl);
                    
                    // Allow same host (with or without port)
                    var isSameHost = uri.Host == baseUri.Host;
                    
                    // Allow localhost for development
                    var isLocalhost = uri.Host == "localhost" || uri.Host == "127.0.0.1" || uri.Host.StartsWith("192.168.");
                    
                    // Allow same domain (for subdomains)
                    var isSameDomain = uri.Host.EndsWith("." + baseUri.Host) || baseUri.Host.EndsWith("." + uri.Host);
                    
                    return isSameHost || isLocalhost || isSameDomain;
                }
                
                // Fallback: allow same host, localhost, or private IPs
                var currentHost = Request.Host.Host;
                return uri.Host == currentHost || 
                       uri.Host == "localhost" || 
                       uri.Host == "127.0.0.1" || 
                       uri.Host.StartsWith("192.168.") ||
                       uri.Host.StartsWith("10.") ||
                       uri.Host.StartsWith("172.");
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Security: Get client IP address for rate limiting and logging
        /// </summary>
        private string GetClientIpAddress()
        {
            var forwardedFor = Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                return forwardedFor.Split(',')[0].Trim();
            }

            var realIp = Request.Headers["X-Real-IP"].FirstOrDefault();
            if (!string.IsNullOrEmpty(realIp))
            {
                return realIp;
            }

            return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        }

        /// <summary>
        /// Security: Check if client is rate limited
        /// </summary>
        private bool IsRateLimited(string clientIp)
        {
            lock (_rateLimitLock)
            {
                var now = DateTime.UtcNow;
                var cutoff = now.AddMinutes(-RATE_LIMIT_WINDOW_MINUTES);

                if (!_externalLoginAttempts.ContainsKey(clientIp))
                {
                    _externalLoginAttempts[clientIp] = new List<DateTime>();
                }

                // Remove old attempts
                _externalLoginAttempts[clientIp].RemoveAll(dt => dt < cutoff);

                // Check if rate limited
                if (_externalLoginAttempts[clientIp].Count >= MAX_EXTERNAL_LOGIN_ATTEMPTS)
                {
                    return true;
                }

                // Record this attempt
                _externalLoginAttempts[clientIp].Add(now);
                return false;
            }
        }
    }
}