using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace RecoverPH_API.Models
{
    public class PaymentTransaction
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(450)]
        public string UserId { get; set; } = string.Empty;

        [Required]
        [StringLength(100)]
        public string TransactionId { get; set; } = string.Empty;

        [Required]
        [StringLength(100)]
        public string CheckoutId { get; set; } = string.Empty;

        [Required]
        [StringLength(50)]
        public string PaymentMethod { get; set; } = string.Empty;

        [Required]
        [Column(TypeName = "decimal(18,2)")]
        public decimal Amount { get; set; }

        [Required]
        [StringLength(3)]
        public string Currency { get; set; } = "PHP";

        [Required]
        [StringLength(50)]
        public string Status { get; set; } = string.Empty;

        [StringLength(50)]
        public string? PlanType { get; set; }

        [StringLength(50)]
        public string? BillingCycle { get; set; }

        public DateTime? SubscriptionStartDate { get; set; }

        public DateTime? SubscriptionEndDate { get; set; }

        [StringLength(500)]
        public string? Description { get; set; }

        [StringLength(1000)]
        public string? PaymentProviderResponse { get; set; }

        [StringLength(100)]
        public string? PaymentProviderTransactionId { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? UpdatedAt { get; set; }

        [StringLength(50)]
        public string? PaymentType { get; set; } // "qr_code", "checkout_form", etc.

        [StringLength(500)]
        public string? RedirectUrl { get; set; }

        [StringLength(500)]
        public string? PaymentUrl { get; set; }

        // Navigation property
        [ForeignKey("UserId")]
        public virtual ApplicationUser? User { get; set; }
    }

    public class PaymentTransactionDto
    {
        public string UserId { get; set; } = string.Empty;
        public string TransactionId { get; set; } = string.Empty;
        public string CheckoutId { get; set; } = string.Empty;
        public string PaymentMethod { get; set; } = string.Empty;
        public decimal Amount { get; set; }
        public string Currency { get; set; } = "PHP";
        public string Status { get; set; } = string.Empty;
        public string? PlanType { get; set; }
        public string? BillingCycle { get; set; }
        public DateTime? SubscriptionStartDate { get; set; }
        public DateTime? SubscriptionEndDate { get; set; }
        public string? Description { get; set; }
        public string? PaymentProviderResponse { get; set; }
        public string? PaymentProviderTransactionId { get; set; }
        public string? PaymentType { get; set; }
        public string? RedirectUrl { get; set; }
        public string? PaymentUrl { get; set; }
    }

    public class PaymentTransactionResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public PaymentTransaction? Data { get; set; }
        public List<string> Errors { get; set; } = new List<string>();
    }
}