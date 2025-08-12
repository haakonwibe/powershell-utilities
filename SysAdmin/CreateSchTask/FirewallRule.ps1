<#
.SYNOPSIS
    Creates firewall rules for Microsoft Teams for each user profile.

.DESCRIPTION
    This script scans user profiles for the Teams executable and creates inbound firewall rules
    for TCP and UDP protocols if they do not already exist. It should be run with elevated permissions.

.PARAMETER ExcludedUsers
    An array of user profile names to exclude from processing. Default excludes 'Public' and built-in administrator accounts.

.PARAMETER TeamsRelativePath
    The relative path from the user profile directory to the Teams executable. Defaults to 'AppData\Local\Microsoft\Teams\current\Teams.exe'.

.EXAMPLE
    .\FirewallRule.ps1

.NOTES
    Author: Haakon Wibe
    Date: 05.11.2018
#>

param(
    [string[]]$ExcludedUsers = @('Public', 'Default', 'All Users', 'Default User'),
    [string]$TeamsRelativePath = 'AppData\Local\Microsoft\Teams\current\Teams.exe'
)

try {
    # Get user profiles excluding specified users
    $userProfiles = Get-ChildItem -Path "$env:SystemDrive\Users" -Directory | Where-Object { $_.Name -notin $ExcludedUsers }

    foreach ($user in $userProfiles) {
        $teamsPath = Join-Path -Path $user.FullName -ChildPath $TeamsRelativePath

        if (Test-Path -Path $teamsPath) {
            # Check if firewall rules already exist for this program
            $existingRules = Get-NetFirewallRule -Action Allow -Program $teamsPath -ErrorAction SilentlyContinue

            if (-not $existingRules) {
                $ruleName = "Teams Inbound for $($user.Name)"
                Write-Host "Creating firewall rules for $($user.Name)..."

                foreach ($protocol in @('TCP', 'UDP')) {
                    New-NetFirewallRule -DisplayName "$ruleName ($protocol)" -Direction Inbound -Profile Domain -Program $teamsPath -Action Allow -Protocol $protocol -ErrorAction Stop
                }

                Write-Host "Firewall rules created for $($user.Name)."
            } else {
                Write-Host "Firewall rules already exist for $($user.Name). Skipping."
            }
        } else {
            Write-Host "Teams executable not found for $($user.Name). Skipping."
        }
    }
} catch {
    Write-Error "An error occurred: $_"
}
