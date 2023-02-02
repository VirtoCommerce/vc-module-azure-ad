using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using VirtoCommerce.AzureAD.Core.Models;
using VirtoCommerce.AzureAD.Data.Services;
using VirtoCommerce.Platform.Core.Modularity;
using VirtoCommerce.Platform.Security.ExternalSignIn;

namespace VirtoCommerce.AzureAD.Web;

public class Module : IModule, IHasConfiguration
{
    public ManifestModuleInfo ModuleInfo { get; set; }
    public IConfiguration Configuration { get; set; }

    public void Initialize(IServiceCollection serviceCollection)
    {
        var azureAdSection = Configuration.GetSection("AzureAd");

        if (azureAdSection.GetChildren().Any())
        {
            var options = new AzureADOptions();
            azureAdSection.Bind(options);
            serviceCollection.Configure<AzureADOptions>(azureAdSection);

            if (options.Enabled)
            {
                var authBuilder = new AuthenticationBuilder(serviceCollection);

                //https://docs.microsoft.com/en-us/azure/active-directory/develop/microsoft-identity-web
                authBuilder.AddOpenIdConnect(options.AuthenticationType, options.AuthenticationCaption,
                    openIdConnectOptions =>
                    {
                        switch (options.ValidateIssuer)
                        {
                            // Multitenant Azure AD issuer validation
                            // https://thomaslevesque.com/2018/12/24/multitenant-azure-ad-issuer-validation-in-asp-net-core/
                            case ValidateIssuerType.MultitenantAzureAD:
                                openIdConnectOptions.TokenValidationParameters.IssuerValidator = MultitenantAzureADIssuerValidator.ValidateIssuerWithPlaceholder;
                                break;
                            case ValidateIssuerType.Disabled:
                                openIdConnectOptions.TokenValidationParameters = new TokenValidationParameters { ValidateIssuer = false };
                                break;
                            default:
                                // Default behaviour
                                break;
                        }

                        openIdConnectOptions.ClientId = options.ApplicationId;

                        openIdConnectOptions.Authority = $"{options.AzureAdInstance}{options.TenantId}";
                        openIdConnectOptions.UseTokenLifetime = true;
                        openIdConnectOptions.RequireHttpsMetadata = false;
                        openIdConnectOptions.SignInScheme = IdentityConstants.ExternalScheme;
                        openIdConnectOptions.MetadataAddress = options.MetadataAddress;

                        var serviceDescriptor = serviceCollection.FirstOrDefault(descriptor => descriptor.ServiceType == typeof(JwtSecurityTokenHandler));
                        if (serviceDescriptor?.ImplementationInstance is JwtSecurityTokenHandler defaultTokenHandler)
                        {
                            openIdConnectOptions.SecurityTokenValidator = defaultTokenHandler;
                        }
                    });

                // register default external provider implementation
                serviceCollection.AddSingleton<AzureADExternalSignInProvider>();
                serviceCollection.AddSingleton(provider => new ExternalSignInProviderConfiguration
                {
                    AuthenticationType = "AzureAD",
                    Provider = provider.GetService<AzureADExternalSignInProvider>(),
                });
            }
        }
    }

    public void PostInitialize(IApplicationBuilder appBuilder)
    {
        // Nothing to do here
    }

    public void Uninstall()
    {
        // Nothing to do here
    }
}
