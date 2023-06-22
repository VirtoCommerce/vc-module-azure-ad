using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using VirtoCommerce.AzureAD.Core.Models;
using VirtoCommerce.Platform.Security.ExternalSignIn;

namespace VirtoCommerce.AzureAD.Data.Services;

public class AzureADExternalSignInProvider : IExternalSignInProvider
{
    private readonly AzureADOptions _azureAdOptions;

    public AzureADExternalSignInProvider(IOptions<AzureADOptions> azureAdOptions)
    {
        _azureAdOptions = azureAdOptions.Value;
    }

    public bool AllowCreateNewUser => _azureAdOptions.AllowCreateNewUser;

    public int Priority => _azureAdOptions.Priority;

    public bool HasLoginForm => _azureAdOptions.HasLoginForm;

    public string GetUserName(ExternalLoginInfo externalLoginInfo)
    {
        var userName = externalLoginInfo.Principal.FindFirstValue(ClaimTypes.Upn);

        if (string.IsNullOrWhiteSpace(userName) && _azureAdOptions.UsePreferredUsername)
        {
            userName = externalLoginInfo.Principal.FindFirstValue("preferred_username");
        }

        if (string.IsNullOrWhiteSpace(userName) && _azureAdOptions.UseEmail)
        {
            userName = externalLoginInfo.Principal.FindFirstValue(ClaimTypes.Email);
        }

        if (string.IsNullOrWhiteSpace(userName))
        {
            throw new InvalidOperationException("Received external login info does not have an UPN claim or DefaultUserName.");
        }

        return userName;
    }

    public string GetUserType()
    {
        return _azureAdOptions.DefaultUserType ?? "Manager";
    }

    public string[] GetUserRoles()
    {
        return _azureAdOptions.DefaultUserRoles;
    }
}
