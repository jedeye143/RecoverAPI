using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RecoverPH_API.Data;
using RecoverPH_API.Models;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace RecoverPH_API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class PaymentTransactionController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<PaymentTransactionController> _logger;

        public PaymentTransactionController(ApplicationDbContext context, ILogger<PaymentTransactionController> logger)
        {
            _context = context;
            _logger = logger;
        }

        /// <summary>
        /// Save a successful payment transaction (called by mobile app or web app)
        /// </summary>
        [HttpPost("save")]
        [Authorize] // Add authorization to ensure only authenticated users can save transactions
        public async Task<IActionResult> SavePaymentTransaction([FromBody] PaymentTransactionDto dto)
        {
            try
            {
                _logger.LogInformation($"[PaymentTransactionController] Received save request for user {dto.UserId}");
                _logger.LogInformation($"[PaymentTransactionController] Transaction ID: {dto.TransactionId}");
                _logger.LogInformation($"[PaymentTransactionController] Amount: {dto.Amount}");
                _logger.LogInformation($"[PaymentTransactionController] Plan: {dto.PlanType}");

                // Get the authenticated user ID from the token
                var authenticatedUserId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value ?? 
                                        User.FindFirst("userId")?.Value ?? 
                                        User.FindFirst("id")?.Value ?? 
                                        User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                _logger.LogInformation($"[PaymentTransactionController] Authenticated user ID: {authenticatedUserId}");

                // Log all claims for debugging
                var claims = User.Claims.ToList();
                _logger.LogInformation($"[PaymentTransactionController] Total claims: {claims.Count}");
                foreach (var claim in claims.Take(5)) // Log first 5 claims
                {
                    _logger.LogInformation($"[PaymentTransactionController] Claim: {claim.Type} = {claim.Value}");
                }

                // Use the authenticated user ID if dto.UserId is empty
                if (string.IsNullOrEmpty(dto.UserId) && !string.IsNullOrEmpty(authenticatedUserId))
                {
                    dto.UserId = authenticatedUserId;
                    _logger.LogInformation($"[PaymentTransactionController] Using authenticated user ID: {dto.UserId}");
                }

                // Ensure the user can only save transactions for themselves (unless admin)
                if (!User.IsInRole("Admin") && dto.UserId != authenticatedUserId)
                {
                    _logger.LogWarning($"[PaymentTransactionController] User {authenticatedUserId} attempted to save transaction for user {dto.UserId}");
                    return Forbid("You can only save transactions for yourself");
                }

                // Validate required fields
                if (string.IsNullOrEmpty(dto.UserId) || 
                    string.IsNullOrEmpty(dto.TransactionId) || 
                    string.IsNullOrEmpty(dto.CheckoutId) ||
                    dto.Amount <= 0)
                {
                    return BadRequest(new PaymentTransactionResponse
                    {
                        Success = false,
                        Message = "Missing required fields",
                        Errors = new List<string> { "UserId, TransactionId, CheckoutId, and Amount are required" }
                    });
                }

                // Check if transaction already exists
                var existingTransaction = await _context.PaymentTransactions
                    .FirstOrDefaultAsync(pt => pt.TransactionId == dto.TransactionId);

                if (existingTransaction != null)
                {
                    _logger.LogWarning($"Transaction {dto.TransactionId} already exists");
                    return Conflict(new PaymentTransactionResponse
                    {
                        Success = false,
                        Message = "Transaction already exists",
                        Data = existingTransaction
                    });
                }

                // Verify user exists
                var user = await _context.Users.FindAsync(dto.UserId);
                if (user == null)
                {
                    return NotFound(new PaymentTransactionResponse
                    {
                        Success = false,
                        Message = "User not found",
                        Errors = new List<string> { $"User with ID {dto.UserId} not found" }
                    });
                }

                // Normalize plan/billing and compute subscription dates if missing
                var planNorm = (dto.PlanType ?? "essential").ToLowerInvariant();
                var billingNorm = (dto.BillingCycle ?? "monthly").ToLowerInvariant();
                var startAt = dto.SubscriptionStartDate ?? DateTime.UtcNow;
                DateTime? endAt = dto.SubscriptionEndDate;
                if (!endAt.HasValue)
                {
                    TimeSpan duration = planNorm switch
                    {
                        "free" or "freetrial" => TimeSpan.FromDays(7),
                        "essential" => billingNorm == "yearly" ? TimeSpan.FromDays(365) : TimeSpan.FromDays(30),
                        "premium" => billingNorm == "yearly" ? TimeSpan.FromDays(365) : TimeSpan.FromDays(30),
                        _ => TimeSpan.FromDays(30)
                    };
                    endAt = startAt.Add(duration);
                }

                // Create new payment transaction
                var paymentTransaction = new PaymentTransaction
                {
                    UserId = dto.UserId,
                    TransactionId = dto.TransactionId,
                    CheckoutId = dto.CheckoutId,
                    PaymentMethod = dto.PaymentMethod,
                    Amount = dto.Amount,
                    Currency = dto.Currency,
                    Status = dto.Status,
                    PlanType = dto.PlanType,
                    BillingCycle = dto.BillingCycle,
                    SubscriptionStartDate = startAt,
                    SubscriptionEndDate = endAt,
                    Description = string.IsNullOrWhiteSpace(dto.Description) ? $"{planNorm} Plan - {billingNorm} Billing" : dto.Description,
                    PaymentProviderResponse = dto.PaymentProviderResponse,
                    PaymentProviderTransactionId = dto.PaymentProviderTransactionId,
                    PaymentType = dto.PaymentType,
                    RedirectUrl = dto.RedirectUrl,
                    PaymentUrl = dto.PaymentUrl,
                    CreatedAt = DateTime.UtcNow
                };

                _context.PaymentTransactions.Add(paymentTransaction);
                await _context.SaveChangesAsync();

                // Update user subscription if payment is successful
                if (dto.Status.ToLower() == "success" || dto.Status.ToLower() == "completed")
                {
                    await UpdateUserSubscription(user, dto);
                }

                _logger.LogInformation($"Payment transaction saved successfully with ID {paymentTransaction.Id}");

                return Ok(new PaymentTransactionResponse
                {
                    Success = true,
                    Message = "Payment transaction saved successfully",
                    Data = paymentTransaction
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving payment transaction");
                return StatusCode(500, new PaymentTransactionResponse
                {
                    Success = false,
                    Message = "Internal server error",
                    Errors = new List<string> { ex.Message }
                });
            }
        }

        /// <summary>
        /// Get payment transactions for a specific user
        /// </summary>
        [HttpGet("user/{userId}")]
        [Authorize]
        public async Task<IActionResult> GetUserPaymentTransactions(string userId, [FromQuery] int page = 1, [FromQuery] int pageSize = 10)
        {
            try
            {
                // Verify the requesting user can access this data
                var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (currentUserId != userId && !User.IsInRole("Admin"))
                {
                    return Forbid("You can only access your own payment transactions");
                }

                var query = _context.PaymentTransactions
                    .Where(pt => pt.UserId == userId)
                    .OrderByDescending(pt => pt.CreatedAt);

                var totalCount = await query.CountAsync();
                var transactions = await query
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .ToListAsync();

                return Ok(new
                {
                    success = true,
                    data = transactions,
                    pagination = new
                    {
                        page,
                        pageSize,
                        totalCount,
                        totalPages = (int)Math.Ceiling((double)totalCount / pageSize)
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error retrieving payment transactions for user {userId}");
                return StatusCode(500, new { success = false, message = "Internal server error" });
            }
        }

        /// <summary>
        /// Get a specific payment transaction by ID
        /// </summary>
        [HttpGet("{id}")]
        [Authorize]
        public async Task<IActionResult> GetPaymentTransaction(int id)
        {
            try
            {
                var transaction = await _context.PaymentTransactions
                    .Include(pt => pt.User)
                    .FirstOrDefaultAsync(pt => pt.Id == id);

                if (transaction == null)
                {
                    return NotFound(new { success = false, message = "Payment transaction not found" });
                }

                // Verify the requesting user can access this data
                var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (currentUserId != transaction.UserId && !User.IsInRole("Admin"))
                {
                    return Forbid("You can only access your own payment transactions");
                }

                return Ok(new { success = true, data = transaction });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error retrieving payment transaction {id}");
                return StatusCode(500, new { success = false, message = "Internal server error" });
            }
        }

        /// <summary>
        /// Update payment transaction status (for webhooks or status updates)
        /// </summary>
        [HttpPut("{id}/status")]
        public async Task<IActionResult> UpdatePaymentTransactionStatus(int id, [FromBody] UpdatePaymentStatusDto dto)
        {
            try
            {
                var transaction = await _context.PaymentTransactions
                    .Include(pt => pt.User)
                    .FirstOrDefaultAsync(pt => pt.Id == id);

                if (transaction == null)
                {
                    return NotFound(new { success = false, message = "Payment transaction not found" });
                }

                transaction.Status = dto.Status;
                transaction.PaymentProviderResponse = dto.PaymentProviderResponse;
                transaction.PaymentProviderTransactionId = dto.PaymentProviderTransactionId;
                transaction.UpdatedAt = DateTime.UtcNow;

                // Update user subscription if payment is now successful
                if (dto.Status.ToLower() == "success" || dto.Status.ToLower() == "completed")
                {
                    await UpdateUserSubscription(transaction.User!, new PaymentTransactionDto
                    {
                        PlanType = transaction.PlanType,
                        BillingCycle = transaction.BillingCycle,
                        SubscriptionStartDate = transaction.SubscriptionStartDate,
                        SubscriptionEndDate = transaction.SubscriptionEndDate
                    });
                }

                await _context.SaveChangesAsync();

                return Ok(new { success = true, message = "Payment transaction status updated", data = transaction });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error updating payment transaction status {id}");
                return StatusCode(500, new { success = false, message = "Internal server error" });
            }
        }

        private async Task UpdateUserSubscription(ApplicationUser user, PaymentTransactionDto dto)
        {
            try
            {
                // Also reflect latest subscription choice in ApplicationUser.Subscription for quick lookups
                if (user != null)
                {
                    var plan = string.IsNullOrWhiteSpace(dto.PlanType) ? "Free" : dto.PlanType;
                    var billing = string.IsNullOrWhiteSpace(dto.BillingCycle) ? "None" : dto.BillingCycle;
                    user.Subscription = $"{plan}:{billing}";
                    await _context.SaveChangesAsync();
                    _logger.LogInformation($"Updated user {user.Id} subscription field to {user.Subscription}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error in UpdateUserSubscription for user {user.Id}");
            }
        }
    }

    public class UpdatePaymentStatusDto
    {
        public string Status { get; set; } = string.Empty;
        public string? PaymentProviderResponse { get; set; }
        public string? PaymentProviderTransactionId { get; set; }
    }
}