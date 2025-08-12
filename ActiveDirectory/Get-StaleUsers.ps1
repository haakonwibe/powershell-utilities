<#
.SYNOPSIS
    Finds inactive users in Active Directory based on last logon date.

.DESCRIPTION
    This script queries Active Directory to find users who haven't logged in within a specified number of days.
    It checks LastLogon across all domain controllers and LastLogonTimeStamp to get the most accurate last logon information.

.PARAMETER DaysInactive
    The number of days since last logon to consider a user as inactive (stale). Default is 90 days.

.PARAMETER SearchBase
    The distinguished name of the organizational unit to search. If not specified, searches the entire domain.

.PARAMETER ExportPath
    Optional path to export results to a CSV file.

.PARAMETER IncludeDisabled
    Switch parameter to include disabled accounts in the results. By default, only enabled accounts are checked.

.PARAMETER SkipDCQuery
    Switch parameter to skip querying all domain controllers for LastLogon. This makes the script faster but less accurate.

.EXAMPLE
    .\Get-StaleUsers.ps1 -DaysInactive 60
    Finds all enabled users who haven't logged in for 60 days or more.

.EXAMPLE
    .\Get-StaleUsers.ps1 -DaysInactive 90 -SearchBase "OU=Users,DC=hawkweave,DC=com" -ExportPath "C:\Reports\StaleUsers.csv"
    Finds stale users in a specific OU and exports results to CSV.

.EXAMPLE
    .\Get-StaleUsers.ps1 -DaysInactive 30 -IncludeDisabled -SkipDCQuery
    Finds stale users including disabled accounts but only queries the current DC.

.NOTES
    Author: Haakon Wibe
    Date: Created for powershell-utilities repository
    
    This script requires the ActiveDirectory PowerShell module.
    For accurate results, the script queries all domain controllers for LastLogon data:
    - LastLogon: Most accurate but not replicated between domain controllers
    - LastLogonTimeStamp: Replicated but may be up to 14 days behind actual last logon
    
    Note: Querying all DCs can be slow in large environments. Use -SkipDCQuery for faster results.
#>

param(
    [Parameter(Mandatory = $false)]
    [int]$DaysInactive = 90,

    [Parameter(Mandatory = $false)]
    [string]$SearchBase,

    [Parameter(Mandatory = $false)]
    [string]$ExportPath,

    [switch]$IncludeDisabled,
    
    [switch]$SkipDCQuery
)

# Import Active Directory module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "Failed to import ActiveDirectory module. Ensure RSAT tools are installed."
    exit 1
}

# Calculate the cutoff date
$cutoffDate = (Get-Date).AddDays(-$DaysInactive)

Write-Host "Searching for users inactive since: $($cutoffDate.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Yellow

# Get all domain controllers if not skipping DC query
$domainControllers = @()
if (-not $SkipDCQuery) {
    try {
        Write-Host "Getting list of domain controllers..." -ForegroundColor Cyan
        $domainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
        Write-Host "Found $($domainControllers.Count) domain controller(s): $($domainControllers -join ', ')" -ForegroundColor Cyan
    } catch {
        Write-Warning "Could not get domain controllers list. Falling back to single DC query: $_"
        $SkipDCQuery = $true
    }
}

# Define properties to retrieve
$properties = @('SamAccountName', 'DisplayName', 'LastLogon', 'LastLogonTimeStamp', 'Enabled', 'DistinguishedName', 'EmailAddress', 'Department')

try {
    # Get all users first
    if ($SearchBase) {
        Write-Host "Searching in OU: $SearchBase" -ForegroundColor Green
        if ($IncludeDisabled) {
            $users = Get-ADUser -Filter * -SearchBase $SearchBase -Property $properties
        } else {
            $users = Get-ADUser -Filter "Enabled -eq `$true" -SearchBase $SearchBase -Property $properties
        }
    } else {
        Write-Host "Searching entire domain..." -ForegroundColor Green
        if ($IncludeDisabled) {
            $users = Get-ADUser -Filter * -Property $properties
        } else {
            $users = Get-ADUser -Filter "Enabled -eq `$true" -Property $properties
        }
    }

    Write-Host "Processing $($users.Count) user(s)..." -ForegroundColor Yellow
    
    # Define the output array
    $results = @()
    $processedCount = 0

    foreach ($user in $users) {
        $processedCount++
        if ($processedCount % 50 -eq 0) {
            Write-Host "Processed $processedCount of $($users.Count) users..." -ForegroundColor Gray
        }

        # Get the most recent logon time from both attributes
        $lastLogonDate = $null
        $lastLogonSource = "Never"
        $lastLogonDC = ""
        
        # Check LastLogonTimeStamp first (replicated attribute)
        if ($user.LastLogonTimeStamp -and $user.LastLogonTimeStamp -gt 0) {
            $lastLogonFromTimeStamp = [DateTime]::FromFileTime($user.LastLogonTimeStamp)
            $lastLogonDate = $lastLogonFromTimeStamp
            $lastLogonSource = "LastLogonTimeStamp"
        }
        
        # Check LastLogon across all domain controllers (if not skipping)
        if (-not $SkipDCQuery -and $domainControllers.Count -gt 0) {
            foreach ($dc in $domainControllers) {
                try {
                    $userOnDC = Get-ADUser -Identity $user.SamAccountName -Property LastLogon -Server $dc -ErrorAction SilentlyContinue
                    
                    if ($userOnDC.LastLogon -and $userOnDC.LastLogon -gt 0) {
                        $lastLogonFromDC = [DateTime]::FromFileTime($userOnDC.LastLogon)
                        
                        # Use the most recent logon time
                        if ($lastLogonDate -eq $null -or $lastLogonFromDC -gt $lastLogonDate) {
                            $lastLogonDate = $lastLogonFromDC
                            $lastLogonSource = "LastLogon"
                            $lastLogonDC = $dc
                        }
                    }
                } catch {
                    # Silently continue if we can't query a specific DC
                    continue
                }
            }
        } else {
            # Single DC query for LastLogon
            if ($user.LastLogon -and $user.LastLogon -gt 0) {
                $lastLogonFromLastLogon = [DateTime]::FromFileTime($user.LastLogon)
                
                if ($lastLogonDate -eq $null -or $lastLogonFromLastLogon -gt $lastLogonDate) {
                    $lastLogonDate = $lastLogonFromLastLogon
                    $lastLogonSource = "LastLogon"
                }
            }
        }

        # Determine if user is stale
        $isStale = $false
        $daysSinceLogon = "N/A"
        $lastLogonDisplay = "Never"

        if ($lastLogonDate -eq $null) {
            # Never logged in
            $isStale = $true
        } else {
            $daysSinceLogon = [math]::Round(((Get-Date) - $lastLogonDate).TotalDays)
            $lastLogonDisplay = $lastLogonDate.ToString('yyyy-MM-dd HH:mm:ss')
            
            if ($lastLogonDate -lt $cutoffDate) {
                $isStale = $true
            }
        }

        # Add stale users to results
        if ($isStale) {
            $resultObject = [PSCustomObject]@{
                SamAccountName    = $user.SamAccountName
                DisplayName       = $user.DisplayName
                EmailAddress      = $user.EmailAddress
                Department        = $user.Department
                LastLogon         = $lastLogonDisplay
                DaysSinceLogon    = $daysSinceLogon
                LogonSource       = $lastLogonSource
                Enabled           = $user.Enabled
                DistinguishedName = $user.DistinguishedName
            }
            
            # Add DC info if we queried multiple DCs
            if (-not $SkipDCQuery -and $lastLogonDC) {
                $resultObject | Add-Member -NotePropertyName "SourceDC" -NotePropertyValue $lastLogonDC
            }
            
            $results += $resultObject
        }
    }

    # Display results
    if ($results.Count -eq 0) {
        Write-Host "No stale users found matching the criteria." -ForegroundColor Green
    } else {
        Write-Host "`nFound $($results.Count) stale user(s):" -ForegroundColor Yellow
        $results | Sort-Object -Property DaysSinceLogon -Descending | Format-Table -AutoSize
        
        # Export to CSV if path provided
        if ($ExportPath) {
            try {
                $results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
                Write-Host "Results exported to: $ExportPath" -ForegroundColor Green
            } catch {
                Write-Error "Failed to export results to CSV: $_"
            }
        }
    }

} catch {
    Write-Error "Failed to query Active Directory: $_"
    exit 1
}