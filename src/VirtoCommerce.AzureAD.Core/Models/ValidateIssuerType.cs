namespace VirtoCommerce.AzureAD.Core.Models;

public enum ValidateIssuerType
{
    /// <summary>
    /// Validate Issuer by Generic OpenID Connect provider
    /// </summary>
    Default,
    /// <summary>
    /// Validate Issuer for Multitenant Azure AD
    /// </summary>
    MultitenantAzureAD,
    /// <summary>
    /// Validation of Issuer is disabled
    /// </summary>
    Disabled,
}
