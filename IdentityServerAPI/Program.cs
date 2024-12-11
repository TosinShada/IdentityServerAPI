using System.Reflection;
using System.Text;
using IdentityServerApi.Authentication;
using IdentityServerApi.Authentication.Entities;
using IdentityServerApi.Authentication.Requirements;
using IdentityServerApi.BusinessLayer.Services;
using IdentityServerApi.BusinessLayer.Settings;
using IdentityServerApi.StartupTasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);
ConfigureServices(builder.Services, builder.Configuration);

var app = builder.Build();

IdentityModelEventSource.ShowPII = true;
JsonWebTokenHandler.DefaultInboundClaimTypeMap.Clear();

Configure(app, app.Environment);

app.Run();

void ConfigureServices(IServiceCollection services, IConfiguration configuration)
{
    var jwtSettings = ConfigureSection<JwtSettings>(nameof(JwtSettings));

    services.AddControllers();
    services.AddMemoryCache();
    services.AddHttpContextAccessor();

    services.AddSwaggerGen(options =>
    {
        options.SwaggerDoc("v1", new OpenApiInfo { Title = "IdentityServerApi", Version = "v1" });

        options.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, new OpenApiSecurityScheme
        {
            In = ParameterLocation.Header,
            Description = "Insert the Bearer Token",
            Name = HeaderNames.Authorization,
            Type = SecuritySchemeType.ApiKey
        });

        options.AddSecurityRequirement(new OpenApiSecurityRequirement
        {
            {
                new OpenApiSecurityScheme
                {
                    Reference= new OpenApiReference
                    {
                        Type = ReferenceType.SecurityScheme,
                        Id = JwtBearerDefaults.AuthenticationScheme
                    }
                },
                Array.Empty<string>()
            }
        });

        // Set the comments path for the Swagger JSON and UI.
        var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
        var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
        options.IncludeXmlComments(xmlPath);
    });

    services.AddSqlServer<AuthenticationDbContext>(configuration.GetConnectionString("AuthConnection"));

    services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.Password.RequiredLength = 6;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
    })
    .AddEntityFrameworkStores<AuthenticationDbContext>()
    .AddDefaultTokenProviders();

    services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtSettings.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtSettings.Audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecurityKey)),
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.Zero
        };
    });

    services.AddSingleton<IAuthorizationHandler, MinimumAgeHandler>();
    //services.AddScoped<IAuthorizationHandler, UserActiveHandler>();

    services.AddAuthorization(options =>
    {
        var policyBuilder = new AuthorizationPolicyBuilder().RequireAuthenticatedUser();
        options.FallbackPolicy = options.DefaultPolicy = policyBuilder.Build();

        options.AddPolicy("UserActive", policy =>
        {
            policy.Requirements.Add(new UserActiveRequirement());
        });

        options.AddPolicy("TwoFactorEnabled", policy =>
        {
            policy.RequireClaim(CustomClaimTypes.Amr, "mfa");
        });

        options.AddPolicy("SuperApplication", policy =>
        {
            policy.RequireClaim(CustomClaimTypes.ApplicationId, "42");
        });

        options.AddPolicy("AdministratorOrPowerUser", policy =>
        {
            policy.RequireRole(RoleNames.Administrator, RoleNames.PowerUser);
        });

        options.AddPolicy("AtLeast18", policy =>
        {
            policy.Requirements.Add(new MinimumAgeRequirement(18));
        });

        options.AddPolicy("AtLeast21", policy =>
        {
            policy.Requirements.Add(new MinimumAgeRequirement(21));
        });
    });

    services.AddScoped<IIdentityService, IdentityService>();
    services.AddScoped<IUserService, UserService>();
    services.AddScoped<IAuthenticatorService, AuthenticatorService>();

    services.AddHostedService<AuthenticationStartupTask>();

    T ConfigureSection<T>(string sectionName) where T : class
    {
        var section = configuration.GetSection(sectionName);
        var settings = section.Get<T>();
        services.Configure<T>(section);

        return settings;
    }
}

void Configure(WebApplication application, IWebHostEnvironment env)
{
    application.UseHttpsRedirection();

    if (env.IsDevelopment())
    {
        application.UseSwagger();
        application.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "IdentityServerApi v1"));
    }

    application.UseRouting();

    application.UseAuthentication();
    application.UseAuthorization();

    application.MapControllers();
}