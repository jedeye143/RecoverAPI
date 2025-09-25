using Microsoft.AspNetCore.Identity;

namespace RecoverPH_API.Models
{
    public class ApplicationUser : IdentityUser
    {
        // Extend with profile fields
        public string? FullName { get; set; }
        public string? DisplayName { get; set; } = string.Empty;
        public DateOnly BirthDate { get; set; }
        public string? Gender { get; set; }
        public string? Subscription { get; set; }
        public bool IsProfileComplete { get; set; } = false;
        
        // Note: Subscription-related fields moved to PaymentTransaction table
        // - SubscriptionPlan, SubscriptionBilling, SubscriptionStartDate, 
        // - SubscriptionEndDate, HasUsedFreeTrial are now managed via PaymentService
    }
}
