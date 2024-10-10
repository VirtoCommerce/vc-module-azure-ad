using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Validators;
using VirtoCommerce.AzureAD.Core.Models;
using VirtoCommerce.AzureAD.Data.Services;
using VirtoCommerce.Platform.Core.Modularity;
using VirtoCommerce.Platform.Core.Security.ExternalSignIn;
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
                        openIdConnectOptions.ClientId = options.ApplicationId;
                        openIdConnectOptions.Authority = $"{options.AzureAdInstance}{options.TenantId}{options.VersionSuffix}";
                        openIdConnectOptions.UseTokenLifetime = true;
                        openIdConnectOptions.SignInScheme = IdentityConstants.ExternalScheme;
                        openIdConnectOptions.MetadataAddress = options.MetadataAddress;

                        switch (options.ValidateIssuer)
                        {
                            // Multitenant Azure AD issuer validation
                            // https://thomaslevesque.com/2018/12/24/multitenant-azure-ad-issuer-validation-in-asp-net-core/
                            case ValidateIssuerType.MultitenantAzureAD:
                                openIdConnectOptions.TokenValidationParameters.IssuerValidator =
                                    AadIssuerValidator.GetAadIssuerValidator(openIdConnectOptions.Authority).Validate;
                                break;
                            case ValidateIssuerType.Disabled:
                                openIdConnectOptions.TokenValidationParameters.ValidateIssuer = false;
                                break;
                        }

                        openIdConnectOptions.Events.OnRedirectToIdentityProvider = context =>
                        {
                            var oidcUrl = context.Properties.GetOidcUrl();
                            if (!string.IsNullOrEmpty(oidcUrl))
                            {
                                context.ProtocolMessage.RedirectUri = oidcUrl;
                            }
                            return Task.CompletedTask;
                        };
                    });

                // register default external provider implementation
                serviceCollection.AddSingleton<AzureADExternalSignInProvider>();
                serviceCollection.AddSingleton(provider => new ExternalSignInProviderConfiguration
                {
                    AuthenticationType = options.AuthenticationType,
                    Provider = provider.GetService<AzureADExternalSignInProvider>(),
                    LogoUrl = "Modules/$(VirtoCommerce.AzureAD)/Content/provider-logo.webp"
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
