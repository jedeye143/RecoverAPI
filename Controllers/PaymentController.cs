using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using RecoverPH_API.Services;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace RecoverPH_API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class PaymentController : ControllerBase
    {
        private readonly ILogger<PaymentController> _logger;
        private readonly MayaPaymentService _mayaPaymentService;
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;
        private readonly string _aspUrl;
        private readonly string _webAppUrl;
        private readonly PaymentService _paymentService;

        public PaymentController(ILogger<PaymentController> logger, MayaPaymentService mayaPaymentService, IConfiguration configuration, HttpClient httpClient, PaymentService paymentService)
        {
            _logger = logger;
            _mayaPaymentService = mayaPaymentService;
            _configuration = configuration;
            _httpClient = httpClient;
            _aspUrl = _configuration["AuthApi:APSUrlHttps"] ?? "";
            _webAppUrl = _configuration["WebApp:BaseUrl"] ?? "https://localhost:7164";
            _paymentService = paymentService;
        }

        [HttpPost("create-maya-payment")]
        public async Task<IActionResult> CreateMayaPayment([FromBody] CreateMayaCheckoutRequest request)
        {
            try
            {
                _logger.LogInformation("Creating real Maya payment for {PaymentMethod}", request.PaymentMethod);

                // Determine payment type based on method
                bool isWalletPayment = request.PaymentMethod == "gcash" || request.PaymentMethod == "maya_wallet";

                // Determine return base URL for redirects (fallback to configured web app URL)
                var returnBase = !string.IsNullOrWhiteSpace(request.ReturnBaseUrl)
                    ? request.ReturnBaseUrl.TrimEnd('/')
                    : (_webAppUrl?.TrimEnd('/') ?? "https://localhost:7164");

                // Compute dynamic price based on plan/billing
                decimal amount = request.Amount;
                if (amount <= 0)
                {
                    var plan = (request.Plan ?? "essential").ToLowerInvariant();
                    var billing = (request.EssentialType ?? "monthly").ToLowerInvariant();
                    if (plan == "premium")
                    {
                        amount = 2000m; // yearly only
                    }
                    else if (plan == "essential")
                    {
                        amount = billing == "yearly" ? 1000m : 199m;
                    }
                    else if (plan == "free")
                    {
                        amount = 0m;
                    }
                    else
                    {
                        amount = 299m; // fallback
                    }
                }

                // Generate a stable reference ID we can use on redirect to save transaction
                var referenceId = Guid.NewGuid().ToString();

                if (isWalletPayment)
                {
                    // Use Pay with Maya for wallet payments (QR code)
                    var mayaRequest = new MayaPayWithMayaRequest
                    {
                        TotalAmount = new MayaPayWithMayaTotalAmount
                        {
                            Value = amount,
                            Currency = "PHP"
                        },
                        Buyer = new MayaPayWithMayaBuyer
                        {
                            FirstName = "Premium",
                            LastName = "User",
                            Contact = "+639000000000",
                            Email = "user@example.com"
                        },
                        RedirectUrl = new MayaPayWithMayaRedirectUrl
                        {
                            Success = $"{returnBase}/PremiumJourney/SubscriptionSuccess?plan={request.Plan}&billing={request.EssentialType}&payment={request.PaymentMethod}&transactionId={referenceId}&amount={amount}",
                            Failure = $"{returnBase}/PremiumJourney/Step4?status=failed&plan={request.Plan}&billing={request.EssentialType}&payment={request.PaymentMethod}&transactionId={referenceId}",
                            Cancel = $"{returnBase}/PremiumJourney/Step4?status=cancelled&plan={request.Plan}&billing={request.EssentialType}&payment={request.PaymentMethod}&transactionId={referenceId}"
                        },
                        RequestReferenceNumber = referenceId,
                        Metadata = new Dictionary<string, object>
                        {
                            { "merchant", "RecoverPH" },
                            { "product", "Premium Protection" },
                            { "description", "Enhanced blocking features for serious recovery" },
                            { "pf", new Dictionary<string, object>
                                {
                                    { "smi", "test_merchant_123" },
                                    { "smn", "RecoverPH" },
                                    { "mci", "Manila" },
                                    { "mpc", "608" },
                                    { "mco", "PHL" }
                                }
                            }
                        }
                    };

                    var mayaResponse = await _mayaPaymentService.CreatePaymentAsync(mayaRequest);

                    // Send SignalR notification to mobile app
                    await SendPaymentNotificationAsync(request.UserId, "payment_created", new
                    {
                        checkoutId = mayaResponse.Id,
                        paymentType = "qr_code",
                        status = "created",
                        paymentMethod = request.PaymentMethod,
                        plan = request.Plan,
                        billingCycle = request.EssentialType,
                        amount = amount
                    });

                    return Ok(new
                    {
                        success = true,
                        checkoutId = mayaResponse.Id,
                        checkoutUrl = mayaResponse.RedirectUrl,
                        paymentUrl = mayaResponse.PaymentUrl,
                        paymentType = "qr_code",
                        clientKey = _configuration["Maya:PayWithMayaPublicKey"],
                        paymentMethod = request.PaymentMethod
                    });
                }
                else
                {
                    // Use Maya Checkout for card/bank payments (form)
                    var checkoutRequest = new MayaCheckoutRequest
                    {
                        TotalAmount = new MayaTotalAmount
                        {
                            Value = request.Amount,
                            Currency = "PHP"
                        },
                        Buyer = new MayaBuyer
                        {
                            FirstName = "Premium",
                            LastName = "User",
                            Contact = new MayaContactDetails
                            {
                                Phone = "+639000000000"
                            },
                            Email = "user@example.com"
                        },
                        Items = new List<MayaItem>
                        {
                            new MayaItem
                            {
                                Name = "Premium Protection",
                                Description = "Enhanced blocking features for serious recovery",
                                Amount = new MayaItemAmount
                                {
                                    Value = amount,
                                    Currency = "PHP"
                                },
                                Quantity = 1,
                                TotalAmount = new MayaItemTotalAmount
                                {
                                    Value = amount,
                                    Currency = "PHP"
                                }
                            }
                        },
                        RedirectUrl = new MayaRedirectUrl
                        {
                            Success = $"{returnBase}/PremiumJourney/SubscriptionSuccess?plan={request.Plan}&billing={request.EssentialType}&payment={request.PaymentMethod}&transactionId={referenceId}&amount={amount}",
                            Failure = $"{returnBase}/PremiumJourney/Step4?status=failed&plan={request.Plan}&billing={request.EssentialType}&payment={request.PaymentMethod}&transactionId={referenceId}",
                            Cancel = $"{returnBase}/PremiumJourney/Step4?status=cancelled&plan={request.Plan}&billing={request.EssentialType}&payment={request.PaymentMethod}&transactionId={referenceId}"
                        },
                        RequestReferenceNumber = referenceId
                    };

                    var checkoutResponse = await _mayaPaymentService.CreateCheckoutAsync(checkoutRequest);

                    // Send SignalR notification to mobile app
                    await SendPaymentNotificationAsync(request.UserId, "payment_created", new
                    {
                        checkoutId = checkoutResponse.CheckoutId,
                        paymentType = "checkout_form",
                        status = "created",
                        paymentMethod = request.PaymentMethod,
                        plan = request.Plan,
                        billingCycle = request.EssentialType,
                        amount = amount
                    });

                    return Ok(new
                    {
                        success = true,
                        checkoutId = checkoutResponse.CheckoutId,
                        checkoutUrl = checkoutResponse.RedirectUrl,
                        paymentUrl = checkoutResponse.PaymentUrl,
                        paymentType = "checkout_form",
                        clientKey = _configuration["Maya:CheckoutPublicKey"],
                        paymentMethod = request.PaymentMethod
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating Maya payment");
                return StatusCode(500, new { success = false, message = "Maya payment processing error: " + ex.Message });
            }
        }

        [HttpPost("process-maya-payment")]
        public async Task<IActionResult> ProcessMayaPayment([FromBody] ProcessMayaPaymentRequest request)
        {
            try
            {
                _logger.LogInformation("Processing real Maya payment");

                // Create real Maya single payment request
                var mayaRequest = new MayaSinglePaymentRequest
                {
                    TotalAmount = new MayaTotalAmount
                    {
                        Value = request.Amount,
                        Currency = "PHP"
                    },
                    Buyer = new MayaBuyer
                    {
                        FirstName = request.CustomerInfo?.Name?.Split(' ').FirstOrDefault() ?? "Premium",
                        LastName = request.CustomerInfo?.Name?.Split(' ').Skip(1).FirstOrDefault() ?? "User",
                        Contact = new MayaContactDetails
                        {
                            Phone = "+639000000000"
                        },
                        Email = request.CustomerInfo?.Email ?? "user@example.com"
                    },
                    Items = new List<MayaItem>
                    {
                        new MayaItem
                        {
                            Name = "Premium Protection",
                            Description = "Enhanced blocking features for serious recovery",
                            Amount = new MayaItemAmount
                            {
                                Value = request.Amount,
                                Currency = "PHP"
                            },
                            Quantity = 1,
                            TotalAmount = new MayaItemTotalAmount
                            {
                                Value = request.Amount,
                                Currency = "PHP"
                            }
                        }
                    },
                    RedirectUrl = new MayaRedirectUrl
                    {
                        Success = $"{_aspUrl}/Premium/Success?id={request.UserId}",
                        Failure = $"{_aspUrl}/Premium/Failed?id={request.UserId}",
                        Cancel = $"{_aspUrl}/Premium/Index?id={request.UserId}"
                    },
                    RequestReferenceNumber = Guid.NewGuid().ToString()
                };

                // Call real Maya API
                var mayaResponse = await _mayaPaymentService.CreateSinglePaymentAsync(mayaRequest);

                return Ok(new
                {
                    success = true,
                    message = "Maya payment created successfully! Redirecting to payment page...",
                    paymentId = mayaResponse.Id,
                    paymentUrl = mayaResponse.PaymentUrl,
                    redirectUrl = mayaResponse.RedirectUrl,
                    status = mayaResponse.Status
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing Maya payment");
                return StatusCode(500, new { success = false, message = "Maya payment processing error: " + ex.Message });
            }
        }

        [HttpPost("create-maya-payment-method")]
        public async Task<IActionResult> CreateMayaPaymentMethod([FromBody] CreateMayaPaymentMethodRequest request)
        {
            try
            {
                // Mock Maya payment method creation
                _logger.LogInformation($"Maya payment method creation requested for {request.Type} but Maya backend not implemented");

                // For demo purposes, simulate different behavior based on payment method
                if (request.Type == "gcash")
                {
                    return Ok(new
                    {
                        success = true,
                        sourceId = "maya_gcash_source_123",
                        checkoutUrl = "https://checkout.gcash.com/pay/demo_gcash_checkout_123", // Mock GCash URL
                        type = "redirect",
                        message = "Redirecting to GCash for payment processing..."
                    });
                }
                else if (request.Type == "maya_wallet")
                {
                    return Ok(new
                    {
                        success = true,
                        sourceId = "maya_wallet_source_123",
                        checkoutUrl = "https://checkout.maya.ph/pay/demo_maya_checkout_123", // Mock Maya URL
                        type = "redirect",
                        message = "Redirecting to Maya Wallet for payment processing..."
                    });
                }
                else
                {
                    // For card and bank transfer, show a form instead of redirect
                    return Ok(new
                    {
                        success = true,
                        sourceId = "maya_form_source_123",
                        type = "form",
                        message = "Please complete the payment form below"
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error creating Maya payment method: {ex.Message}");
                return StatusCode(500, new { success = false, message = "Maya payment method creation error" });
            }
        }

        [HttpPost("webhook")]
        public async Task<IActionResult> Webhook([FromBody] object webhookData)
        {
            try
            {
                // Mock Maya webhook processing
                _logger.LogInformation("Maya webhook received but Maya backend not implemented");
                return Ok();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Maya webhook processing error: {ex.Message}");
                return BadRequest();
            }
        }

        // Request Models
        public class CreateMayaCheckoutRequest
        {
            public decimal Amount { get; set; } = 299;
            public string Currency { get; set; } = "PHP";
            public string PaymentMethod { get; set; } = string.Empty;
            public string UserId { get; set; } = string.Empty;
            public string Plan { get; set; } = "Premium"; // free, essential, premium
            public string EssentialType { get; set; } = "Monthly"; // monthly, yearly
            public string ReturnBaseUrl { get; set; } = string.Empty; // e.g., https://192.168.1.3:7206 or https://localhost:7193
        }

        public class ProcessMayaPaymentRequest
        {
            public string PaymentMethodId { get; set; } = string.Empty;
            public string CheckoutId { get; set; } = string.Empty;
            public decimal Amount { get; set; } = 299;
            public string UserId { get; set; } = string.Empty;
            public CustomerInfo CustomerInfo { get; set; } = new CustomerInfo();
        }

        public class CreateMayaPaymentMethodRequest
        {
            public string Type { get; set; } = "card";
            public object Details { get; set; } = new object();
            public object Billing { get; set; } = new object();
        }

        public class CustomerInfo
        {
            public string Name { get; set; } = string.Empty;
            public string Phone { get; set; } = string.Empty;
            public string Email { get; set; } = string.Empty;
        }

        /// <summary>
        /// Send SignalR notification to mobile app via web app
        /// </summary>
        private async Task SendPaymentNotificationAsync(string userId, string eventType, object data)
        {
            try
            {
                var payload = new
                {
                    userId = userId,
                    eventType = eventType,
                    data = data,
                    timestamp = DateTime.UtcNow
                };

                var json = System.Text.Json.JsonSerializer.Serialize(payload);
                var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync($"{_webAppUrl}/api/SignalR/payment-notification", content);
                
                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation($"SignalR notification sent successfully for user {userId}");
                }
                else
                {
                    _logger.LogWarning($"Failed to send SignalR notification for user {userId}: {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error sending SignalR notification for user {userId}");
            }
        }

        
        // GET USER SUBSCRIPTION INFO
        [HttpGet("subscription")]
        [Authorize]
        public async Task<IActionResult> GetSubscriptionInfo()
        {
            try
            {
                var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
                if (string.IsNullOrEmpty(userId))
                    return Unauthorized(new { message = "Invalid token" });

                var paymentSummary = await _paymentService.GetUserPaymentSummaryAsync(userId);

                return Ok(new
                {
                    success = true,
                    data = new
                    {
                        currentSubscription = paymentSummary.CurrentSubscription,
                        hasUsedFreeTrial = paymentSummary.HasUsedFreeTrial,
                        hasActiveSubscription = paymentSummary.HasActiveSubscription,
                        totalAmountSpent = paymentSummary.TotalAmountSpent,
                        totalTransactions = paymentSummary.TotalTransactions
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting subscription info");
                return StatusCode(500, new { success = false, message = "Internal server error" });
            }
        }

        // CREATE FREE TRIAL
        [HttpPost("create-free-trial")]
        [Authorize]
        public async Task<IActionResult> CreateFreeTrial([FromBody] CreateFreeTrialDto model)
        {
            try
            {
                var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value ?? 
                             User.FindFirst("userId")?.Value ?? 
                             User.FindFirst("id")?.Value ?? 
                             User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                
                if (string.IsNullOrEmpty(userId))
                    return Unauthorized(new { message = "Invalid token" });

                // Check if user already used free trial
                if (await _paymentService.HasUsedFreeTrialAsync(userId))
                {
                    return BadRequest(new { success = false, message = "Free trial already used" });
                }

                var freeTrialTransaction = await _paymentService.CreateFreeTrialAsync(userId, model.TrialDays);
                
                if (freeTrialTransaction == null)
                {
                    return BadRequest(new { success = false, message = "Failed to create free trial" });
                }

                return Ok(new
                {
                    success = true,
                    message = "Free trial created successfully",
                    data = new
                    {
                        transactionId = freeTrialTransaction.TransactionId,
                        startDate = freeTrialTransaction.SubscriptionStartDate,
                        endDate = freeTrialTransaction.SubscriptionEndDate,
                        trialDays = model.TrialDays
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating free trial");
                return StatusCode(500, new { success = false, message = "Internal server error" });
            }
        }

        // GET SUBSCRIPTION HISTORY
        [HttpGet("subscription-history")]
        [Authorize]
        public async Task<IActionResult> GetSubscriptionHistory()
        {
            try
            {
                var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
                if (string.IsNullOrEmpty(userId))
                    return Unauthorized(new { message = "Invalid token" });

                var subscriptionHistory = await _paymentService.GetSubscriptionHistoryAsync(userId);

                return Ok(new
                {
                    success = true,
                    data = subscriptionHistory
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting subscription history");
                return StatusCode(500, new { success = false, message = "Internal server error" });
            }
        }

        // CANCEL SUBSCRIPTION
        [HttpPost("cancel-subscription")]
        [Authorize]
        public async Task<IActionResult> CancelSubscription([FromBody] CancelSubscriptionDto model)
        {
            try
            {
                var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
                if (string.IsNullOrEmpty(userId))
                    return Unauthorized(new { message = "Invalid token" });

                var success = await _paymentService.CancelCurrentSubscriptionAsync(userId, model.Reason);
                
                if (!success)
                {
                    return BadRequest(new { success = false, message = "No active subscription to cancel" });
                }

                return Ok(new
                {
                    success = true,
                    message = "Subscription cancelled successfully"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cancelling subscription");
                return StatusCode(500, new { success = false, message = "Internal server error" });
            }
        }

        public class CreateFreeTrialDto
        {
            public int TrialDays { get; set; } = 7;
        }

        public class CancelSubscriptionDto
        {
            public string Reason { get; set; } = "User requested cancellation";
        }


    }
}