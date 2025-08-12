<#
.SYNOPSIS
    Connects to Exchange Online using modern authentication.

.DESCRIPTION
    This script establishes a connection to Exchange Online using the Exchange Online PowerShell V2 module (EXO V2), which supports modern authentication and is more secure than basic authentication.

.PARAMETER Username
    The username (UPN) of the account to use for authentication.

.PARAMETER UseMFA
    A switch parameter. Include this if the account uses Multi-Factor Authentication (MFA).

.EXAMPLE
    .\Connect-ExchangeOnline.ps1 -Username user@domain.com -UseMFA

.NOTES
    Author: Haakon Wibe
    Date: 20.01.2016

    This script requires the ExchangeOnlineManagement module. If it's not installed, the script will attempt to install it.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Username,

    [switch]$UseMFA
)

# Ensure the Exchange Online Management module is installed
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    try {
        Write-Host "Installing ExchangeOnlineManagement module..."
        Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
    } catch {
        Write-Error "Failed to install ExchangeOnlineManagement module: $_"
        exit 1
    }
}

Import-Module ExchangeOnlineManagement

try {
    if ($UseMFA) {
        # Connect using MFA
        Connect-ExchangeOnline -UserPrincipalName $Username -ShowProgress $false
    } else {
        # Connect using non-MFA credentials
        $SecurePassword = Read-Host -Prompt "Enter password" -AsSecureString
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $SecurePassword
        Connect-ExchangeOnline -Credential $Credential -ShowProgress $false
    }
    Write-Host "Connected to Exchange Online successfully."
} catch {
    Write-Error "Failed to connect to Exchange Online: $_"
}

# Uncomment the following line to disconnect the session when done
# Disconnect-ExchangeOnline -Confirm:$false
