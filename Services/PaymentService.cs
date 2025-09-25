using Microsoft.EntityFrameworkCore;
using RecoverPH_API.Data;
using RecoverPH_API.Models;

namespace RecoverPH_API.Services
{
    public class PaymentService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<PaymentService> _logger;

        public PaymentService(ApplicationDbContext context, ILogger<PaymentService> logger)
        {
            _context = context;
            _logger = logger;
        }

        /// <summary>
        /// Check if user has used their free trial
        /// </summary>
        public async Task<bool> HasUsedFreeTrialAsync(string userId)
        {
            try
            {
                var freeTrialTransaction = await _context.PaymentTransactions
                    .FirstOrDefaultAsync(pt => pt.UserId == userId && 
                                             (pt.PlanType == "FreeTrial" || pt.PlanType == "Free" || 
                                              (pt.PlanType == "Free" && pt.BillingCycle == "Trial")) && 
                                             pt.Status == "success");

                return freeTrialTransaction != null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error checking free trial status for user {userId}");
                return false;
            }
        }

        /// <summary>
        /// Get current active subscription for user
        /// </summary>
        public async Task<SubscriptionInfo?> GetCurrentSubscriptionAsync(string userId)
        {
            try
            {
                var currentSubscription = await _context.PaymentTransactions
                    .Where(pt => pt.UserId == userId && 
                               pt.Status == "success" && 
                               pt.SubscriptionEndDate.HasValue &&
                               pt.SubscriptionEndDate.Value > DateTime.UtcNow)
                    .OrderByDescending(pt => pt.SubscriptionEndDate)
                    .FirstOrDefaultAsync();

                if (currentSubscription == null)
                    return null;

                return new SubscriptionInfo
                {
                    PlanType = currentSubscription.PlanType ?? "Free",
                    BillingCycle = currentSubscription.BillingCycle ?? "None",
                    StartDate = currentSubscription.SubscriptionStartDate,
                    EndDate = currentSubscription.SubscriptionEndDate,
                    IsActive = currentSubscription.SubscriptionEndDate > DateTime.UtcNow,
                    TransactionId = currentSubscription.TransactionId
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting current subscription for user {userId}");
                return null;
            }
        }

        /// <summary>
        /// Get subscription history for user
        /// </summary>
        public async Task<List<SubscriptionInfo>> GetSubscriptionHistoryAsync(string userId)
        {
            try
            {
                var subscriptions = await _context.PaymentTransactions
                    .Where(pt => pt.UserId == userId && 
                               pt.Status == "success" && 
                               !string.IsNullOrEmpty(pt.PlanType))
                    .OrderByDescending(pt => pt.CreatedAt)
                    .Select(pt => new SubscriptionInfo
                    {
                        PlanType = pt.PlanType ?? "Free",
                        BillingCycle = pt.BillingCycle ?? "None",
                        StartDate = pt.SubscriptionStartDate,
                        EndDate = pt.SubscriptionEndDate,
                        IsActive = pt.SubscriptionEndDate.HasValue && pt.SubscriptionEndDate.Value > DateTime.UtcNow,
                        TransactionId = pt.TransactionId,
                        Amount = pt.Amount,
                        CreatedAt = pt.CreatedAt
                    })
                    .ToListAsync();

                return subscriptions;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting subscription history for user {userId}");
                return new List<SubscriptionInfo>();
            }
        }

        /// <summary>
        /// Create free trial transaction for user
        /// </summary>
        public async Task<PaymentTransaction?> CreateFreeTrialAsync(string userId, int trialDays = 7)
        {
            try
            {
                // Check if user already used free trial
                if (await HasUsedFreeTrialAsync(userId))
                {
                    _logger.LogWarning($"User {userId} has already used free trial");
                    return null;
                }

                var freeTrialTransaction = new PaymentTransaction
                {
                    UserId = userId,
                    TransactionId = $"FREETRIAL-{DateTime.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid().ToString("N")[..8]}",
                    CheckoutId = $"FREETRIAL-{Guid.NewGuid().ToString("N")[..12]}",
                    PaymentMethod = "free_trial",
                    Amount = 0,
                    Currency = "PHP",
                    Status = "success",
                    PlanType = "Free",
                    BillingCycle = "Trial",
                    SubscriptionStartDate = DateTime.UtcNow,
                    SubscriptionEndDate = DateTime.UtcNow.AddDays(trialDays),
                    Description = $"{trialDays}-day Free Trial",
                    PaymentType = "free_trial",
                    CreatedAt = DateTime.UtcNow
                };

                _context.PaymentTransactions.Add(freeTrialTransaction);

                // Update ApplicationUser.Subscription field
                var user = await _context.Users.FindAsync(userId);
                if (user != null)
                {
                    user.Subscription = "Free:Trial";
                    _context.Users.Update(user);
                }

                await _context.SaveChangesAsync();

                _logger.LogInformation($"Free trial created for user {userId}, expires on {freeTrialTransaction.SubscriptionEndDate}");
                return freeTrialTransaction;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error creating free trial for user {userId}");
                return null;
            }
        }

        /// <summary>
        /// Create subscription transaction for user
        /// </summary>
        public async Task<PaymentTransaction?> CreateSubscriptionTransactionAsync(string userId, string plan, string billingCycle, string paymentMethod, string checkoutId, string transactionId)
        {
            try
            {
                var (amount, duration) = GetPlanPricing(plan, billingCycle);
                
                var subscriptionTransaction = new PaymentTransaction
                {
                    UserId = userId,
                    TransactionId = transactionId,
                    CheckoutId = checkoutId,
                    PaymentMethod = paymentMethod,
                    Amount = amount,
                    Currency = "PHP",
                    Status = "success",
                    PlanType = plan,
                    BillingCycle = billingCycle,
                    SubscriptionStartDate = DateTime.UtcNow,
                    SubscriptionEndDate = DateTime.UtcNow.Add(duration),
                    Description = $"{plan} Plan - {billingCycle} Billing",
                    PaymentType = "subscription",
                    CreatedAt = DateTime.UtcNow
                };

                _context.PaymentTransactions.Add(subscriptionTransaction);
                await _context.SaveChangesAsync();

                _logger.LogInformation($"Subscription created for user {userId}: {plan}/{billingCycle}, expires on {subscriptionTransaction.SubscriptionEndDate}");
                return subscriptionTransaction;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error creating subscription for user {userId}");
                return null;
            }
        }

        /// <summary>
        /// Get pricing and duration for plan and billing cycle
        /// </summary>
        private (decimal amount, TimeSpan duration) GetPlanPricing(string plan, string billingCycle)
        {
            return plan.ToLower() switch
            {
                "free" => (0, TimeSpan.FromDays(7)), // Free trial
                "freetrial" => (0, TimeSpan.FromDays(7)), // Free trial (mobile app uses this)
                "essential" => billingCycle.ToLower() switch
                {
                    "monthly" => (199, TimeSpan.FromDays(30)),
                    "yearly" => (1500, TimeSpan.FromDays(365)), // Match mobile app pricing
                    _ => (199, TimeSpan.FromDays(30))
                },
                "premium" => billingCycle.ToLower() switch
                {
                    "monthly" => (299, TimeSpan.FromDays(30)),
                    "yearly" => (2000, TimeSpan.FromDays(365)), // Match mobile app pricing
                    _ => (299, TimeSpan.FromDays(30))
                },
                _ => (299, TimeSpan.FromDays(30)) // Default to Premium monthly
            };
        }

        /// <summary>
        /// Check if user has any active subscription (including free trial)
        /// </summary>
        public async Task<bool> HasActiveSubscriptionAsync(string userId)
        {
            try
            {
                var activeSubscription = await _context.PaymentTransactions
                    .AnyAsync(pt => pt.UserId == userId && 
                                  pt.Status == "success" && 
                                  pt.SubscriptionEndDate.HasValue &&
                                  pt.SubscriptionEndDate.Value > DateTime.UtcNow);

                return activeSubscription;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error checking active subscription for user {userId}");
                return false;
            }
        }

        /// <summary>
        /// Get user's payment summary
        /// </summary>
        public async Task<UserPaymentSummary> GetUserPaymentSummaryAsync(string userId)
        {
            try
            {
                var currentSubscription = await GetCurrentSubscriptionAsync(userId);
                var hasUsedFreeTrial = await HasUsedFreeTrialAsync(userId);
                var hasActiveSubscription = await HasActiveSubscriptionAsync(userId);

                var totalSpent = await _context.PaymentTransactions
                    .Where(pt => pt.UserId == userId && pt.Status == "success" && pt.Amount > 0)
                    .SumAsync(pt => pt.Amount);

                var transactionCount = await _context.PaymentTransactions
                    .CountAsync(pt => pt.UserId == userId && pt.Status == "success");

                return new UserPaymentSummary
                {
                    UserId = userId,
                    CurrentSubscription = currentSubscription,
                    HasUsedFreeTrial = hasUsedFreeTrial,
                    HasActiveSubscription = hasActiveSubscription,
                    TotalAmountSpent = totalSpent,
                    TotalTransactions = transactionCount
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting payment summary for user {userId}");
                return new UserPaymentSummary { UserId = userId };
            }
        }

        /// <summary>
        /// Cancel current subscription (mark as cancelled but don't delete)
        /// </summary>
        public async Task<bool> CancelCurrentSubscriptionAsync(string userId, string reason = "User requested cancellation")
        {
            try
            {
                var currentSubscription = await _context.PaymentTransactions
                    .Where(pt => pt.UserId == userId && 
                               pt.Status == "success" && 
                               pt.SubscriptionEndDate.HasValue &&
                               pt.SubscriptionEndDate.Value > DateTime.UtcNow)
                    .OrderByDescending(pt => pt.SubscriptionEndDate)
                    .FirstOrDefaultAsync();

                if (currentSubscription == null)
                {
                    _logger.LogWarning($"No active subscription found for user {userId}");
                    return false;
                }

                // Create a cancellation record
                var cancellationTransaction = new PaymentTransaction
                {
                    UserId = userId,
                    TransactionId = $"CANCEL-{DateTime.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid().ToString("N")[..8]}",
                    CheckoutId = currentSubscription.CheckoutId,
                    PaymentMethod = "cancellation",
                    Amount = 0,
                    Currency = "PHP",
                    Status = "cancelled",
                    PlanType = currentSubscription.PlanType,
                    BillingCycle = currentSubscription.BillingCycle,
                    SubscriptionStartDate = currentSubscription.SubscriptionStartDate,
                    SubscriptionEndDate = currentSubscription.SubscriptionEndDate, // Keep original end date
                    Description = $"Subscription cancellation: {reason}",
                    PaymentType = "cancellation",
                    PaymentProviderResponse = reason,
                    CreatedAt = DateTime.UtcNow
                };

                _context.PaymentTransactions.Add(cancellationTransaction);
                await _context.SaveChangesAsync();

                _logger.LogInformation($"Subscription cancelled for user {userId}. Reason: {reason}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error cancelling subscription for user {userId}");
                return false;
            }
        }
    }

    // DTOs for the PaymentService
    public class SubscriptionInfo
    {
        public string PlanType { get; set; } = "Free";
        public string BillingCycle { get; set; } = "None";
        public DateTime? StartDate { get; set; }
        public DateTime? EndDate { get; set; }
        public bool IsActive { get; set; }
        public string TransactionId { get; set; } = string.Empty;
        public decimal Amount { get; set; }
        public DateTime CreatedAt { get; set; }
    }

    public class UserPaymentSummary
    {
        public string UserId { get; set; } = string.Empty;
        public SubscriptionInfo? CurrentSubscription { get; set; }
        public bool HasUsedFreeTrial { get; set; }
        public bool HasActiveSubscription { get; set; }
        public decimal TotalAmountSpent { get; set; }
        public int TotalTransactions { get; set; }
    }
}