using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using RecoverPH_API.Services;
using RecoverPH_API.Data;
using RecoverPH_API.Models;
using Swashbuckle.AspNetCore.Filters;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

// Mobile development remove when production
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(5137); // HTTP
    options.ListenAnyIP(7164, listenOptions => listenOptions.UseHttps()); // HTTPS
});


builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey
    });

    options.OperationFilter<SecurityRequirementsOperationFilter>();
});


builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Use ApplicationUser instead of IdentityUser
// This allows us to extend the fields 


builder.Services.AddIdentityApiEndpoints<ApplicationUser>()
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

// Persist Data Protection keys so correlation cookies survive app restarts during OAuth flow
var keysDirectory = Path.Combine(AppContext.BaseDirectory, "dp-keys");
Directory.CreateDirectory(keysDirectory);
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(keysDirectory))
    .SetApplicationName("RecoverPH-API");

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    // Cookie scheme used only for external provider temp state (correlation)
    .AddCookie("External", o =>
    {
        o.Cookie.Name = ".RGPH.External";
        o.Cookie.SameSite = SameSiteMode.None;
        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {   
            ValidateIssuer = true,
            ValidIssuer = builder.Configuration["JWT:Issuer"],

            ValidateAudience = true,
            ValidAudience = builder.Configuration["JWT:Audience"],

            ValidateLifetime = true,

            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["JWT:SigningKey"])
            )
        };
    })
    .AddGoogle(googleOptions =>
    {
        googleOptions.ClientId = builder.Configuration["Authentication:Google:ClientId"] ?? string.Empty;
        googleOptions.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"] ?? string.Empty;
        // Redirect back to this path after Google completes auth
        googleOptions.CallbackPath = "/signin-google";
        // Use dedicated cookie scheme for correlation/state
        googleOptions.SignInScheme = "External";
        googleOptions.CorrelationCookie.SameSite = SameSiteMode.None;
        googleOptions.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
    })
    .AddFacebook(fbOptions =>
    {
        fbOptions.AppId = builder.Configuration["Authentication:Facebook:AppId"] ?? string.Empty;
        fbOptions.AppSecret = builder.Configuration["Authentication:Facebook:AppSecret"] ?? string.Empty;
        fbOptions.CallbackPath = "/signin-facebook";
        fbOptions.SignInScheme = "External";
        fbOptions.CorrelationCookie.SameSite = SameSiteMode.None;
        fbOptions.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
    });

builder.Services.AddAuthorization();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins("https://localhost:7193") // ASP MVC frontend
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

// Add Maya payment service
builder.Services.Configure<MayaConfig>(builder.Configuration.GetSection("Maya"));
builder.Services.AddHttpClient<MayaPaymentService>();
builder.Services.AddScoped<MayaPaymentService>();

// Add HttpClient for SignalR notifications to web app
builder.Services.AddHttpClient();

// Add PaymentService
builder.Services.AddScoped<PaymentService>();

// Auth API HttpClient (with dev HTTPS cert bypass)
var authApiBaseUrl = builder.Configuration["AuthApi:BaseUrl"] ?? string.Empty;
builder.Services.AddHttpClient("AuthApi", client =>
{
    if (!string.IsNullOrWhiteSpace(authApiBaseUrl))
    {
        client.BaseAddress = new Uri(authApiBaseUrl.TrimEnd('/'));
    }
})
.ConfigurePrimaryHttpMessageHandler(() =>
{
    var handler = new HttpClientHandler();
    if (builder.Environment.IsDevelopment())
    {
        handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
    }
    return handler;
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Map Identity API with ApplicationUser for custom fields
app.MapIdentityApi<ApplicationUser>();

app.UseHttpsRedirection();

// Accept forwarded headers if running behind a proxy (scheme/host), important for OAuth callbacks
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost
});

app.UseCors("AllowFrontend");

// Ensure cookie policy compatible with OAuth correlation cookies
app.UseCookiePolicy(new CookiePolicyOptions
{
    MinimumSameSitePolicy = SameSiteMode.None,
    Secure = CookieSecurePolicy.Always
});

app.UseAuthentication(); //MUST ALWAYS COME BEFORE AUTHORIZATION! DO NOT RE-ORGANIZE!
app.UseAuthorization();

app.MapControllers();

app.Run();
