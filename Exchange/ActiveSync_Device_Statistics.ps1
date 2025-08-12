<#
.SYNOPSIS
    Retrieves ActiveSync device statistics for user mailboxes in a specified domain.

.DESCRIPTION
    This script retrieves all user mailboxes matching a specified domain and then gathers ActiveSync device statistics for each mailbox. It handles multiple devices per user and outputs the information in a structured format.

.PARAMETER Domain
    The domain to filter user mailboxes (e.g., "domain.com").

.EXAMPLE
    .\Get-ActiveSyncDeviceStatistics.ps1 -Domain "domain.com"

.NOTES
    Author: Haakon Wibe
    Date: 20.01.2016
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Domain
)

# Ensure necessary modules are imported
Import-Module -Name ExchangePowerShell -ErrorAction SilentlyContinue

# Retrieve all user mailboxes matching the specified domain
try {
    $mailboxes = Get-Mailbox -RecipientTypeDetails UserMailbox -Filter { UserPrincipalName -like "*@$Domain" } -ResultSize Unlimited
} catch {
    Write-Error "Failed to retrieve mailboxes: $_"
    exit
}

# Initialize output collection
$output = @()

foreach ($mailbox in $mailboxes) {
    Write-Verbose "Processing mailbox: $($mailbox.UserPrincipalName)"

    try {
        # Retrieve ActiveSync device statistics for the mailbox
        $deviceStats = Get-ActiveSyncDeviceStatistics -Mailbox $mailbox.Identity -ErrorAction Stop

        foreach ($device in $deviceStats) {
            $output += [PSCustomObject]@{
                User               = $mailbox.UserPrincipalName
                DeviceType         = $device.DeviceType
                DeviceOS           = $device.DeviceOS
                DeviceFriendlyName = $device.DeviceFriendlyName
                LastSyncTime       = $device.LastSuccessSync
            }
        }
    } catch {
        Write-Warning "No ActiveSync devices found for mailbox $($mailbox.UserPrincipalName)."
        $output += [PSCustomObject]@{
            User               = $mailbox.UserPrincipalName
            DeviceType         = "N/A"
            DeviceOS           = "N/A"
            DeviceFriendlyName = "N/A"
            LastSyncTime       = "N/A"
        }
    }
}

# Output the results
$output | Select-Object User, DeviceType, DeviceFriendlyName, DeviceOS, LastSyncTime | Sort-Object User
