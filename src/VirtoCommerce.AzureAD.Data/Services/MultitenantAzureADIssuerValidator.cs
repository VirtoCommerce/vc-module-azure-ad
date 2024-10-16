using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace VirtoCommerce.AzureAD.Data.Services;

/// <summary>
/// Multitenant Azure AD issuer validation in ASP.NET Core
/// If you use Azure AD authentication and want to allow users from any tenant to connect to your ASP.NET Core application,
/// you need to configure the Azure AD app as multi-tenant, and use a “wildcard” tenant id such as organizations or common in the authority URL.
/// The problem when you do that is that with the default configuration, the token validation will fail because the issuer in the
/// token won’t match the issuer specified in the OpenID metadata. 
/// https://thomaslevesque.com/2018/12/24/multitenant-azure-ad-issuer-validation-in-asp-net-core/
/// </summary>
[Obsolete("Use Microsoft.IdentityModel.Validators.AadIssuerValidator", DiagnosticId = "VC0009", UrlFormat = "https://docs.virtocommerce.org/products/products-virto3-versions")]
public static class MultitenantAzureADIssuerValidator
{
    public static string ValidateIssuerWithPlaceholder(string issuer, SecurityToken token, TokenValidationParameters parameters)
    {
        // Accepts any issuer of the form "https://login.microsoftonline.com/{tenantid}/v2.0",
        // where tenantid is the tid from the token.

        var tokenTenantId = GetTenantId(token);

        if (!string.IsNullOrEmpty(tokenTenantId))
        {
            var validIssuers = (parameters.ValidIssuers ?? Enumerable.Empty<string>())
                .Append(parameters.ValidIssuer)
                .Where(i => !string.IsNullOrEmpty(i));

            if (validIssuers.Any(i => i.Replace("{tenantid}", tokenTenantId) == issuer))
            {
                return issuer;
            }
        }

        // Recreate the exception that is thrown by default
        // when issuer validation fails
        throw new SecurityTokenInvalidIssuerException($"IDX10205: Issuer validation failed. Issuer: '{issuer}'. Did not match: validationParameters.ValidIssuer: '{parameters.ValidIssuer ?? "null"}' or validationParameters.ValidIssuers: '{GetValidIssuersString(parameters)}'.")
        {
            InvalidIssuer = issuer
        };
    }

    private static string GetTenantId(SecurityToken token)
    {
        return token switch
        {
            JwtSecurityToken jwtSecurityToken => jwtSecurityToken.Payload.TryGetValue("tid", out var value) ? value as string : null,
            JsonWebToken jsonWebToken => jsonWebToken.TryGetClaim("tid", out var claim) ? claim.Value : null,
            _ => null
        };
    }

    private static string GetValidIssuersString(TokenValidationParameters parameters)
    {
        if (parameters.ValidIssuers == null)
        {
            return "null";
        }

        if (!parameters.ValidIssuers.Any())
        {
            return "empty";
        }

        return string.Join(", ", parameters.ValidIssuers);
    }
}
