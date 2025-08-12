<#
.SYNOPSIS
    Matches GPOs with corresponding AD Computer objects and Security Groups.

.DESCRIPTION
    This script retrieves Group Policy Objects (GPOs) that match a specified pattern,
    attempts to find corresponding Active Directory (AD) Computer objects and Security Groups,
    and outputs a consolidated report.

.PARAMETER GpoCriteria
    The pattern to match GPO display names.

.PARAMETER GpoPrefixToTrim
    The prefix to remove from GPO display names to obtain the computer name.

.PARAMETER GroupSuffix
    The suffix to append to the computer name to form the security group name pattern.

.PARAMETER GroupSearchBase
    The LDAP path to the Organizational Unit (OU) where security groups are located.

.EXAMPLE
    .\GPO-server-match.ps1 -GpoCriteria "GPO-<SITE>-<OU>" -GpoPrefixToTrim "GPO-<SITE>-" -GroupSuffix "-LOCALADMIN" -GroupSearchBase "OU=LocalAdmin,OU=Groups,DC=example,DC=com"

.NOTES
    Author: Haakon Wibe
    Date: 14.09.2017
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$GpoCriteria,

    [Parameter(Mandatory = $true)]
    [string]$GpoPrefixToTrim,

    [Parameter(Mandatory = $true)]
    [string]$GroupSuffix,

    [Parameter(Mandatory = $true)]
    [string]$GroupSearchBase
)

# Ensure necessary modules are imported
Import-Module -Name GroupPolicy -ErrorAction SilentlyContinue
Import-Module -Name ActiveDirectory -ErrorAction SilentlyContinue

# Get all GPOs matching the criteria
$gpos = Get-GPO -All | Where-Object { $_.DisplayName -match $GpoCriteria }

# Initialize output array
$output = @()

foreach ($gpo in $gpos) {
    # Extract computer name by trimming prefix
    $computerName = $gpo.DisplayName.TrimStart($GpoPrefixToTrim)

    # Formulate security group name pattern
    $groupNamePattern = "*" + $computerName + $GroupSuffix

    # Initialize variables
    $computer = $null
    $securityGroup = $null

    # Attempt to retrieve AD Computer object
    try {
        $computer = Get-ADComputer -Identity $computerName -ErrorAction Stop
    } catch {
        Write-Warning "Computer '$computerName' not found in Active Directory."
    }

    # Attempt to retrieve AD Security Group
    try {
        $securityGroups = Get-ADGroup -Filter { Name -like $groupNamePattern } -SearchBase $GroupSearchBase -ErrorAction Stop
        if ($securityGroups.Count -gt 1) {
            Write-Warning "Multiple security groups found for pattern '$groupNamePattern'. Selecting the first one."
        }
        $securityGroup = $securityGroups | Select-Object -First 1
    } catch {
        Write-Warning "Security group matching '$groupNamePattern' not found in Active Directory."
    }

    # Create output object
    $outputObject = [PSCustomObject]@{
        GPO               = $gpo.DisplayName
        Computer          = if ($computer) { $computer.Name } else { "Not Found" }
        DistinguishedName = if ($computer) { $computer.DistinguishedName } else { "N/A" }
        SecurityGroup     = if ($securityGroup) { $securityGroup.Name } else { "Not Found" }
    }

    $output += $outputObject
}

# Display sorted output
$output | Sort-Object GPO | Select-Object GPO, Computer, DistinguishedName, SecurityGroup
