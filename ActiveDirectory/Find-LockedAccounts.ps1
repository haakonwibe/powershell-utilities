<#
.SYNOPSIS
    Finds and optionally unlocks locked user accounts in Active Directory.

.DESCRIPTION
    This script searches for locked user accounts in Active Directory and displays detailed information
    about each locked account. It can optionally unlock accounts and export results to CSV.

.PARAMETER Domain
    The domain to search for locked accounts. If not specified, uses the current domain.

.PARAMETER UnlockAccounts
    Switch parameter to unlock all found locked accounts after confirmation.

.PARAMETER OutputPath
    Optional path to export results to a CSV file.

.PARAMETER Credential
    PSCredential object for running the script with different credentials.

.PARAMETER Force
    Switch parameter to skip confirmation prompts when unlocking accounts. Use with caution.

.EXAMPLE
    .\Find-LockedAccounts.ps1
    Finds and displays all locked accounts in the current domain.

.EXAMPLE
    .\Find-LockedAccounts.ps1 -Domain "hawkweave.com" -OutputPath "C:\Reports\LockedAccounts.csv"
    Finds locked accounts in the specified domain and exports results to CSV.

.EXAMPLE
    .\Find-LockedAccounts.ps1 -UnlockAccounts
    Finds locked accounts and prompts to unlock them.

.EXAMPLE
    .\Find-LockedAccounts.ps1 -UnlockAccounts -Force
    Finds and unlocks all locked accounts without confirmation prompts.

.NOTES
    Author: Haakon Wibe
    Date: Created for powershell-utilities repository
    
    This script requires the ActiveDirectory PowerShell module and appropriate permissions.
    To unlock accounts, the user must have Account Lockout and Management permissions.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$Domain,

    [switch]$UnlockAccounts,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,

    [switch]$Force
)

# Import Active Directory module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Verbose "Active Directory module imported successfully."
} catch {
    Write-Error "Failed to import ActiveDirectory module. Ensure RSAT tools are installed."
    exit 1
}

Write-Host "Searching for locked user accounts..." -ForegroundColor Yellow

# Build parameters for AD cmdlets
$adParams = @{}

if ($Domain) {
    try {
        # Validate domain exists
        Get-ADDomain -Identity $Domain -ErrorAction Stop | Out-Null
        $adParams.Server = $Domain
        Write-Host "Searching in domain: $Domain" -ForegroundColor Green
    } catch {
        Write-Error "Failed to connect to domain '$Domain': $_"
        exit 1
    }
} else {
    Write-Host "Searching in current domain..." -ForegroundColor Green
}

if ($Credential) {
    $adParams.Credential = $Credential
    Write-Verbose "Using provided credentials."
}

try {
    # Find all locked user accounts using Search-ADAccount (required for PowerShell 7 compatibility)
    Write-Verbose "Querying for locked accounts..."
    $lockedAccountsList = Search-ADAccount @adParams -LockedOut -UsersOnly

    if ($lockedAccountsList.Count -eq 0) {
        Write-Host "No locked user accounts found." -ForegroundColor Green
        exit 0
    }

    Write-Host "Found $($lockedAccountsList.Count) locked account(s)." -ForegroundColor Yellow

    # Get detailed information for each locked account
    $lockedAccounts = @()
    foreach ($account in $lockedAccountsList) {
        try {
            $detailedAccount = Get-ADUser @adParams -Identity $account.SamAccountName -Properties SamAccountName, DisplayName, LastLogonDate, LockedOut, LockoutTime, EmailAddress, Department, DistinguishedName -ErrorAction Stop
            $lockedAccounts += $detailedAccount
        } catch {
            Write-Warning "Failed to get details for account '$($account.SamAccountName)': $_"
            # Add the basic account info even if detailed query fails
            $lockedAccounts += $account
        }
    }

    # Define the output array
    $results = @()

    foreach ($account in $lockedAccounts) {
        Write-Verbose "Processing account: $($account.SamAccountName)"
        
        try {
            # Get lockout location (which DC reported the lockout)
            $lockoutLocation = "Unknown"
            try {
                # Query domain controllers for lockout events
                $domainControllers = Get-ADDomainController @adParams -Filter *
                foreach ($dc in $domainControllers) {
                    try {
                        $dcParams = $adParams.Clone()
                        $dcParams.Server = $dc.HostName
                        $userOnDC = Get-ADUser @dcParams -Identity $account.SamAccountName -Property LockoutTime -ErrorAction SilentlyContinue
                        if ($userOnDC.LockoutTime -and $userOnDC.LockoutTime -gt [DateTime]::MinValue) {
                            $lockoutLocation = $dc.HostName
                            break
                        }
                    } catch {
                        continue
                    }
                }
            } catch {
                Write-Verbose "Could not determine lockout location for $($account.SamAccountName)"
            }

            # Format lockout time
            $lockoutTimeDisplay = "Unknown"
            if ($account.LockoutTime -and $account.LockoutTime -gt [DateTime]::MinValue) {
                $lockoutTimeDisplay = $account.LockoutTime.ToString('yyyy-MM-dd HH:mm:ss')
            }

            # Format last logon time
            $lastLogonDisplay = "Never"
            if ($account.LastLogonDate) {
                $lastLogonDisplay = $account.LastLogonDate.ToString('yyyy-MM-dd HH:mm:ss')
            }

            # Add to results
            $results += [PSCustomObject]@{
                SamAccountName    = $account.SamAccountName
                DisplayName       = $account.DisplayName
                EmailAddress      = $account.EmailAddress
                Department        = $account.Department
                LastLogon         = $lastLogonDisplay
                LockoutTime       = $lockoutTimeDisplay
                LockoutLocation   = $lockoutLocation
                DistinguishedName = $account.DistinguishedName
            }

        } catch {
            Write-Warning "Failed to get details for account '$($account.SamAccountName)': $_"
            
            # Add basic information even if detailed query fails
            $results += [PSCustomObject]@{
                SamAccountName    = $account.SamAccountName
                DisplayName       = $account.DisplayName ?? "Error retrieving details"
                EmailAddress      = ""
                Department        = ""
                LastLogon         = "Unknown"
                LockoutTime       = "Unknown"
                LockoutLocation   = "Unknown"
                DistinguishedName = $account.DistinguishedName
            }
        }
    }

    # Display results
    Write-Host "`nLocked User Accounts:" -ForegroundColor Yellow
    $results | Sort-Object -Property SamAccountName | Format-Table -AutoSize

    # Export to CSV if requested
    if ($OutputPath) {
        try {
            $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
            Write-Host "Results exported to: $OutputPath" -ForegroundColor Green
        } catch {
            Write-Error "Failed to export results to CSV: $_"
        }
    }

    # Unlock accounts if requested
    if ($UnlockAccounts) {
        Write-Host "`nUnlock Operations:" -ForegroundColor Yellow
        
        if (-not $Force) {
            $confirmation = Read-Host "Do you want to unlock all $($results.Count) locked account(s)? (y/N)"
            if ($confirmation -notmatch '^[Yy]$') {
                Write-Host "Unlock operation cancelled." -ForegroundColor Yellow
                exit 0
            }
        }

        $successCount = 0
        $errorCount = 0

        foreach ($account in $lockedAccountsList) {
            try {
                Write-Host "Unlocking account: $($account.SamAccountName)..." -ForegroundColor Cyan
                Unlock-ADAccount @adParams -Identity $account.SamAccountName -ErrorAction Stop
                Write-Host "  ✓ Successfully unlocked $($account.SamAccountName)" -ForegroundColor Green
                $successCount++
            } catch {
                Write-Host "  ✗ Failed to unlock $($account.SamAccountName): $_" -ForegroundColor Red
                $errorCount++
            }
        }

        # Summary
        Write-Host "`nUnlock Summary:" -ForegroundColor Yellow
        Write-Host "  Successfully unlocked: $successCount account(s)" -ForegroundColor Green
        if ($errorCount -gt 0) {
            Write-Host "  Failed to unlock: $errorCount account(s)" -ForegroundColor Red
        }
    }

} catch {
    Write-Error "Failed to query Active Directory for locked accounts: $_"
    exit 1
}

# NOTES:
#   This script requires elevated permissions (Run as Administrator)
#   Required permissions: Account Lockout and Management permissions in AD