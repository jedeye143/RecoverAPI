using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace RecoverPH_API.Services
{
    public class MayaPaymentService
    {
        private readonly HttpClient _httpClient;
        private readonly MayaConfig _mayaConfig;
        private readonly ILogger<MayaPaymentService> _logger;

        public MayaPaymentService(HttpClient httpClient, IOptions<MayaConfig> mayaConfig, ILogger<MayaPaymentService> logger)
        {
            _httpClient = httpClient;
            _mayaConfig = mayaConfig.Value;
            _logger = logger;
            
            // Set up HTTP client for Maya API
            _httpClient.BaseAddress = new Uri(_mayaConfig.BaseUrl);
            _httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
        }

        public async Task<MayaCheckoutResponse> CreateCheckoutAsync(MayaCheckoutRequest request)
        {
            try
            {
                _logger.LogInformation("Creating Maya checkout for amount: {Amount}", request.TotalAmount.Value);

                // Clear any existing authorization header
                _httpClient.DefaultRequestHeaders.Authorization = null;
                
                // Set up authentication for Maya Checkout (uses Public Key)
                var authString = Convert.ToBase64String(Encoding.UTF8.GetBytes(_mayaConfig.CheckoutPublicKey));
                _logger.LogInformation("Maya Checkout Auth String: {AuthString}", authString);
                _logger.LogInformation("Maya Checkout Public Key: {PublicKey}", _mayaConfig.CheckoutPublicKey);
                
                _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
                    "Basic", authString);

                var json = JsonSerializer.Serialize(request, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    WriteIndented = true
                });
                
                _logger.LogInformation("Maya checkout request JSON: {Json}", json);

                var content = new StringContent(json, Encoding.UTF8, "application/json");

                // Debug: Log the full URL being called
                var fullUrl = $"{_httpClient.BaseAddress}checkout/v1/checkouts";
                _logger.LogInformation("Calling Maya Checkout endpoint: {FullUrl}", fullUrl);
                
                var response = await _httpClient.PostAsync("checkout/v1/checkouts", content);

                var responseContent = await response.Content.ReadAsStringAsync();
                _logger.LogInformation("Maya checkout response status: {StatusCode}", response.StatusCode);
                _logger.LogInformation("Maya checkout response: {Response}", responseContent);

                if (response.IsSuccessStatusCode)
                {
                    try
                    {
                        var checkoutResponse = JsonSerializer.Deserialize<MayaCheckoutResponse>(responseContent, new JsonSerializerOptions
                        {
                            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                        });
                        return checkoutResponse;
                    }
                    catch (JsonException ex)
                    {
                        _logger.LogError(ex, "Failed to deserialize Maya checkout response: {Response}", responseContent);
                        throw new InvalidOperationException($"Failed to parse Maya response: {ex.Message}");
                    }
                }
                else
                {
                    _logger.LogError("Maya checkout failed: {StatusCode} - {Content}", response.StatusCode, responseContent);
                    throw new InvalidOperationException($"Maya checkout failed: {response.StatusCode} - {responseContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating Maya checkout");
                throw;
            }
        }

        public async Task<MayaPaymentResponse> CreatePaymentAsync(MayaPayWithMayaRequest request)
        {
            try
            {
                _logger.LogInformation("Creating Maya payment for amount: {Amount}", request.TotalAmount.Value);

                // Clear any existing authorization header
                _httpClient.DefaultRequestHeaders.Authorization = null;
                
                // Set up authentication for Pay with Maya (uses Public Key)
                _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
                    "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(_mayaConfig.PayWithMayaPublicKey)));

                var json = JsonSerializer.Serialize(request, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    WriteIndented = true
                });
                
                _logger.LogInformation("Maya payment request JSON: {Json}", json);

                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync("payby/v2/paymaya/payments", content);

                var responseContent = await response.Content.ReadAsStringAsync();
                _logger.LogInformation("Maya payment response status: {StatusCode}", response.StatusCode);
                _logger.LogInformation("Maya payment response: {Response}", responseContent);

                if (response.IsSuccessStatusCode)
                {
                    try
                    {
                        var paymentResponse = JsonSerializer.Deserialize<MayaPaymentResponse>(responseContent, new JsonSerializerOptions
                        {
                            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                        });
                        return paymentResponse;
                    }
                    catch (JsonException ex)
                    {
                        _logger.LogError(ex, "Failed to deserialize Maya payment response: {Response}", responseContent);
                        throw new InvalidOperationException($"Failed to parse Maya response: {ex.Message}");
                    }
                }
                else
                {
                    _logger.LogError("Maya payment failed: {StatusCode} - {Content}", response.StatusCode, responseContent);
                    throw new InvalidOperationException($"Maya payment failed: {response.StatusCode} - {responseContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating Maya payment");
                throw;
            }
        }

        public async Task<MayaPaymentResponse> CreateSinglePaymentAsync(MayaSinglePaymentRequest request)
        {
            try
            {
                _logger.LogInformation("Creating Maya single payment for amount: {Amount}", request.TotalAmount.Value);

                var json = JsonSerializer.Serialize(request, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });

                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync("/payments/v1/payments", content);

                var responseContent = await response.Content.ReadAsStringAsync();
                _logger.LogInformation("Maya single payment response: {Response}", responseContent);

                if (response.IsSuccessStatusCode)
                {
                    var paymentResponse = JsonSerializer.Deserialize<MayaPaymentResponse>(responseContent, new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    });
                    return paymentResponse;
                }
                else
                {
                    _logger.LogError("Maya single payment failed: {StatusCode} - {Content}", response.StatusCode, responseContent);
                    throw new InvalidOperationException($"Maya single payment failed: {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating Maya single payment");
                throw;
            }
        }

        public async Task<MayaPaymentStatusResponse> GetPaymentStatusAsync(string paymentId)
        {
            try
            {
                _logger.LogInformation("Getting Maya payment status for ID: {PaymentId}", paymentId);

                var response = await _httpClient.GetAsync($"/payments/v1/payments/{paymentId}");

                var responseContent = await response.Content.ReadAsStringAsync();
                _logger.LogInformation("Maya payment status response: {Response}", responseContent);

                if (response.IsSuccessStatusCode)
                {
                    var statusResponse = JsonSerializer.Deserialize<MayaPaymentStatusResponse>(responseContent, new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    });
                    return statusResponse;
                }
                else
                {
                    _logger.LogError("Maya payment status failed: {StatusCode} - {Content}", response.StatusCode, responseContent);
                    throw new InvalidOperationException($"Maya payment status failed: {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting Maya payment status");
                throw;
            }
        }
    }

    public class MayaConfig
    {
        public string Environment { get; set; } = string.Empty;
        public string BaseUrl { get; set; } = string.Empty;
        public string CheckoutPublicKey { get; set; } = string.Empty;
        public string CheckoutSecretKey { get; set; } = string.Empty;
        public string PayWithMayaPublicKey { get; set; } = string.Empty;
        public string PayWithMayaSecretKey { get; set; } = string.Empty;
        public string WebhookSecret { get; set; } = string.Empty;
    }

    // Maya API Request/Response Models
    public class MayaCheckoutRequest
    {
        public MayaTotalAmount TotalAmount { get; set; } = new();
        public MayaBuyer Buyer { get; set; } = new();
        public List<MayaItem> Items { get; set; } = new();
        public MayaRedirectUrl RedirectUrl { get; set; } = new();
        public string RequestReferenceNumber { get; set; } = string.Empty;
    }

    public class MayaTotalAmount
    {
        public decimal Value { get; set; }
        public string Currency { get; set; } = "PHP";
    }

    public class MayaBuyer
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public MayaContactDetails Contact { get; set; } = new();
        public string Email { get; set; } = string.Empty;
    }

    public class MayaContactDetails
    {
        public string Phone { get; set; } = string.Empty;
    }

    public class MayaItem
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public MayaItemAmount Amount { get; set; } = new();
        public int Quantity { get; set; } = 1;
        public MayaItemTotalAmount TotalAmount { get; set; } = new();
    }

    public class MayaItemAmount
    {
        public decimal Value { get; set; }
        public string Currency { get; set; } = "PHP";
    }

    public class MayaItemTotalAmount
    {
        public decimal Value { get; set; }
        public string Currency { get; set; } = "PHP";
    }

    public class MayaRedirectUrl
    {
        public string Success { get; set; } = string.Empty;
        public string Failure { get; set; } = string.Empty;
        public string Cancel { get; set; } = string.Empty;
    }


    public class MayaCheckoutResponse
    {
        public string CheckoutId { get; set; } = string.Empty;
        public string RedirectUrl { get; set; } = string.Empty;
        public string PaymentUrl { get; set; } = string.Empty;
    }

    public class MayaSinglePaymentRequest
    {
        public MayaTotalAmount TotalAmount { get; set; } = new();
        public MayaBuyer Buyer { get; set; } = new();
        public List<MayaItem> Items { get; set; } = new();
        public MayaRedirectUrl RedirectUrl { get; set; } = new();
        public string RequestReferenceNumber { get; set; } = string.Empty;
    }

    public class MayaPaymentResponse
    {
        public string Id { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string PaymentUrl { get; set; } = string.Empty;
        public string RedirectUrl { get; set; } = string.Empty;
    }

    public class MayaPaymentStatusResponse
    {
        public string Id { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public MayaTotalAmount TotalAmount { get; set; } = new();
        public string PaymentUrl { get; set; } = string.Empty;
    }

    // Pay with Maya API Models
    public class MayaPayWithMayaRequest
    {
        public MayaPayWithMayaTotalAmount TotalAmount { get; set; } = new();
        public MayaPayWithMayaBuyer Buyer { get; set; } = new();
        public MayaPayWithMayaRedirectUrl RedirectUrl { get; set; } = new();
        public string RequestReferenceNumber { get; set; } = string.Empty;
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    public class MayaPayWithMayaTotalAmount
    {
        public decimal Value { get; set; }
        public string Currency { get; set; } = "PHP";
    }

    public class MayaPayWithMayaBuyer
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string Contact { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
    }

    public class MayaPayWithMayaRedirectUrl
    {
        public string Success { get; set; } = string.Empty;
        public string Failure { get; set; } = string.Empty;
        public string Cancel { get; set; } = string.Empty;
    }
}
