<#
.SYNOPSIS
    Audits and monitors privileged group memberships in Active Directory for security compliance.

.DESCRIPTION
    This script performs comprehensive auditing of privileged Active Directory groups to identify
    security risks, unauthorized access, and compliance issues. It analyzes group memberships,
    detects changes over time, and generates detailed security reports with recommendations.

.PARAMETER Domain
    The domain to audit privileged groups in. If not specified, uses the current domain.

.PARAMETER OutputPath
    Optional path to save detailed HTML, CSV, and baseline reports.

.PARAMETER AlertOnChanges
    Switch parameter to highlight recent membership changes since last baseline.

.PARAMETER BaselineFile
    Path to existing baseline file for change comparison. If not provided, creates new baseline.

.PARAMETER IncludeNestedGroups
    Switch parameter to recursively check nested group memberships (slower but more thorough).

.PARAMETER ExcludeServiceAccounts
    Switch parameter to filter out service accounts from the audit results.

.PARAMETER CustomGroups
    Optional array of additional group names to audit beyond the default privileged groups.

.PARAMETER DaysInactiveThreshold
    Number of days to consider an account inactive. Default is 90 days.

.PARAMETER PasswordAgeThreshold
    Number of days to consider a password as old. Default is 365 days.

.PARAMETER Credential
    PSCredential object for running the script with different credentials.

.EXAMPLE
    .\Audit-AdminGroups.ps1
    Performs basic audit of all default privileged groups in the current domain.

.EXAMPLE
    .\Audit-AdminGroups.ps1 -Domain "contoso.com" -OutputPath "C:\SecurityAudits\" -BaselineFile "C:\Baselines\AdminGroups_Baseline.xml"
    Audits specified domain, saves reports, and compares against existing baseline.

.EXAMPLE
    .\Audit-AdminGroups.ps1 -IncludeNestedGroups -AlertOnChanges -CustomGroups @("SQL Admins", "VMware Admins")
    Comprehensive audit including nested groups, change detection, and custom groups.

.EXAMPLE
    .\Audit-AdminGroups.ps1 -OutputPath "C:\SecurityAudits\" -ExcludeServiceAccounts -DaysInactiveThreshold 60
    Audits with custom thresholds, excludes service accounts, and saves detailed reports.

.NOTES
    Author: Haakon Wibe
    Date: Created for powershell-utilities repository
    
    This script requires the ActiveDirectory PowerShell module and appropriate read permissions.
    For comprehensive auditing, Domain Admins or equivalent permissions are recommended.
    
    The script automatically creates baselines for future change detection if none exist.
    Output includes console summaries, CSV exports, and professional HTML reports.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$Domain,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [switch]$AlertOnChanges,

    [Parameter(Mandatory = $false)]
    [string]$BaselineFile,

    [switch]$IncludeNestedGroups,

    [switch]$ExcludeServiceAccounts,

    [Parameter(Mandatory = $false)]
    [string[]]$CustomGroups = @(),

    [Parameter(Mandatory = $false)]
    [int]$DaysInactiveThreshold = 90,

    [Parameter(Mandatory = $false)]
    [int]$PasswordAgeThreshold = 365,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential
)

# Initialize script variables
$script:StartTime = Get-Date
$script:AuditResults = @()
$script:SecurityIssues = @()
$script:Changes = @()
$script:Statistics = @{
    TotalGroups = 0
    TotalMembers = 0
    TotalUsers = 0
    TotalComputers = 0
    TotalServiceAccounts = 0
    InactiveAccounts = 0
    DisabledAccounts = 0
    OldPasswords = 0
    MultipleGroupMemberships = 0
}

# Define predefined privileged groups to audit
$PrivilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Print Operators",
    "Power Users",
    "Remote Desktop Users",
    "DHCP Administrators",
    "DNS Admins",
    "Group Policy Creator Owners",
    "Cert Publishers",
    "DnsUpdateProxy",
    "Enterprise Key Admins",
    "Key Admins",
    "Protected Users",
    "Incoming Forest Trust Builders"
)

# Combine with custom groups if provided
$AllGroupsToAudit = $PrivilegedGroups + $CustomGroups

# Import Active Directory module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "Active Directory module imported successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to import ActiveDirectory module. Ensure RSAT tools are installed."
    exit 1
}

# Helper function to write colored output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White",
        [switch]$NoNewline
    )
    
    $params = @{ Object = $Message; ForegroundColor = $Color }
    if ($NoNewline) { $params.Add("NoNewline", $true) }
    
    Write-Host @params
}

# Function to determine if account is a service account
function Test-ServiceAccount {
    param([string]$SamAccountName, [string]$Description, [string]$DisplayName)
    
    $servicePatterns = @(
        "^svc", "^service", "^sql", "^iis", "^web", "^app", "^backup", "^monitoring",
        "service", "admin$", "_admin", "-admin", "system", "batch", "task", "scheduler"
    )
    
    $accountInfo = "$SamAccountName $Description $DisplayName".ToLower()
    
    foreach ($pattern in $servicePatterns) {
        if ($accountInfo -match $pattern) {
            return $true
        }
    }
    return $false
}

# Function to get nested group members recursively
function Get-NestedGroupMembers {
    param(
        [string]$GroupName,
        [hashtable]$ADParams,
        [hashtable]$ProcessedGroups = @{}
    )
    
    # Prevent infinite recursion
    if ($ProcessedGroups.ContainsKey($GroupName)) {
        return @()
    }
    $ProcessedGroups[$GroupName] = $true
    
    $allMembers = @()
    
    try {
        $group = Get-ADGroup @ADParams -Identity $GroupName -ErrorAction Stop
        $members = Get-ADGroupMember @ADParams -Identity $group -ErrorAction Stop
        
        foreach ($member in $members) {
            if ($member.objectClass -eq "group") {
                # Recursively get nested group members
                $nestedMembers = Get-NestedGroupMembers -GroupName $member.SamAccountName -ADParams $ADParams -ProcessedGroups $ProcessedGroups
                $allMembers += $nestedMembers
                
                # Also include the group itself
                $allMembers += $member
            } else {
                $allMembers += $member
            }
        }
    } catch {
        Write-Warning "Failed to get nested members for group '$GroupName': $_"
    }
    
    return $allMembers
}

# Function to analyze group membership
function Get-GroupMembershipAnalysis {
    param(
        [string]$GroupName,
        [hashtable]$ADParams
    )
    
    Write-ColorOutput "Analyzing group: $GroupName" -Color "Cyan"
    
    try {
        # Check if group exists
        $group = Get-ADGroup @ADParams -Identity $GroupName -Properties Description, whenCreated -ErrorAction Stop
        
        # Get group members
        $members = if ($IncludeNestedGroups) {
            Get-NestedGroupMembers -GroupName $GroupName -ADParams $ADParams
        } else {
            Get-ADGroupMember @ADParams -Identity $group -ErrorAction Stop
        }
        
        $groupAnalysis = @{
            GroupName = $GroupName
            GroupDN = $group.DistinguishedName
            Description = $group.Description
            Created = $group.whenCreated
            MemberCount = $members.Count
            Members = @()
            SecurityIssues = @()
        }
        
        $script:Statistics.TotalGroups++
        $script:Statistics.TotalMembers += $members.Count
        
        foreach ($member in $members) {
            try {
                $memberDetails = $null
                $memberType = $member.objectClass
                $lastLogon = "Never"
                $passwordLastSet = "Never"
                $accountEnabled = $null
                $isServiceAccount = $false
                $daysSinceLogon = "N/A"
                $passwordAge = "N/A"
                
                if ($memberType -eq "user") {
                    $memberDetails = Get-ADUser @ADParams -Identity $member.SamAccountName -Properties LastLogonTimeStamp, LastLogonDate, PasswordLastSet, Enabled, Description, Title, Department, whenCreated, AccountExpirationDate -ErrorAction Stop
                    
                    # Calculate last logon
                    if ($memberDetails.LastLogonTimeStamp) {
                        $lastLogon = [DateTime]::FromFileTime($memberDetails.LastLogonTimeStamp).ToString('yyyy-MM-dd HH:mm:ss')
                        $daysSinceLogon = [math]::Round(((Get-Date) - [DateTime]::FromFileTime($memberDetails.LastLogonTimeStamp)).TotalDays)
                    }
                    
                    # Calculate password age
                    if ($memberDetails.PasswordLastSet) {
                        $passwordLastSet = $memberDetails.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss')
                        $passwordAge = [math]::Round(((Get-Date) - $memberDetails.PasswordLastSet).TotalDays)
                    }
                    
                    $accountEnabled = $memberDetails.Enabled
                    $isServiceAccount = Test-ServiceAccount -SamAccountName $member.SamAccountName -Description $memberDetails.Description -DisplayName $memberDetails.DisplayName
                    
                    # Update statistics
                    $script:Statistics.TotalUsers++
                    if ($isServiceAccount) { $script:Statistics.TotalServiceAccounts++ }
                    if (-not $accountEnabled) { $script:Statistics.DisabledAccounts++ }
                    if ($daysSinceLogon -ne "N/A" -and $daysSinceLogon -gt $DaysInactiveThreshold) { $script:Statistics.InactiveAccounts++ }
                    if ($passwordAge -ne "N/A" -and $passwordAge -gt $PasswordAgeThreshold) { $script:Statistics.OldPasswords++ }
                    
                } elseif ($memberType -eq "computer") {
                    $memberDetails = Get-ADComputer @ADParams -Identity $member.SamAccountName -Properties LastLogonTimeStamp, Enabled, Description, whenCreated -ErrorAction Stop
                    
                    if ($memberDetails.LastLogonTimeStamp) {
                        $lastLogon = [DateTime]::FromFileTime($memberDetails.LastLogonTimeStamp).ToString('yyyy-MM-dd HH:mm:ss')
                        $daysSinceLogon = [math]::Round(((Get-Date) - [DateTime]::FromFileTime($memberDetails.LastLogonTimeStamp)).TotalDays)
                    }
                    
                    $accountEnabled = $memberDetails.Enabled
                    $script:Statistics.TotalComputers++
                    
                } elseif ($memberType -eq "group") {
                    $memberDetails = Get-ADGroup @ADParams -Identity $member.SamAccountName -Properties Description, whenCreated -ErrorAction Stop
                }
                
                # Skip service accounts if requested
                if ($ExcludeServiceAccounts -and $isServiceAccount) {
                    continue
                }
                
                $memberInfo = [PSCustomObject]@{
                    GroupName = $GroupName
                    MemberName = $member.SamAccountName
                    DisplayName = if ($memberDetails) { $memberDetails.DisplayName ?? $memberDetails.Name } else { $member.Name }
                    MemberType = $memberType
                    Title = if ($memberDetails -and $memberDetails.Title) { $memberDetails.Title } else { "" }
                    Department = if ($memberDetails -and $memberDetails.Department) { $memberDetails.Department } else { "" }
                    Description = if ($memberDetails) { $memberDetails.Description } else { "" }
                    LastLogon = $lastLogon
                    DaysSinceLogon = $daysSinceLogon
                    PasswordLastSet = $passwordLastSet
                    PasswordAge = $passwordAge
                    AccountEnabled = $accountEnabled
                    IsServiceAccount = $isServiceAccount
                    Created = if ($memberDetails) { $memberDetails.whenCreated } else { "Unknown" }
                    ExpirationDate = if ($memberDetails -and $memberDetails.AccountExpirationDate) { $memberDetails.AccountExpirationDate } else { "Never" }
                    DistinguishedName = $member.DistinguishedName
                }
                
                $groupAnalysis.Members += $memberInfo
                
                # Identify security issues
                $issues = @()
                
                if ($memberType -eq "user") {
                    if (-not $accountEnabled) {
                        $issues += "Disabled account in privileged group"
                    }
                    
                    if ($daysSinceLogon -ne "N/A" -and $daysSinceLogon -gt $DaysInactiveThreshold) {
                        $issues += "Inactive account ($daysSinceLogon days since logon)"
                    }
                    
                    if ($passwordAge -ne "N/A" -and $passwordAge -gt $PasswordAgeThreshold) {
                        $issues += "Old password ($passwordAge days old)"
                    }
                    
                    if ($isServiceAccount) {
                        $issues += "Service account in administrative group"
                    }
                    
                    # Check for generic accounts
                    $genericPatterns = @("admin", "administrator", "test", "temp", "generic", "shared")
                    foreach ($pattern in $genericPatterns) {
                        if ($member.SamAccountName.ToLower() -match $pattern) {
                            $issues += "Potentially generic/shared account"
                            break
                        }
                    }
                }
                
                if ($issues.Count -gt 0) {
                    $securityIssue = [PSCustomObject]@{
                        GroupName = $GroupName
                        MemberName = $member.SamAccountName
                        MemberType = $memberType
                        Issues = $issues -join "; "
                        Severity = if ($issues -match "Disabled|Inactive") { "High" } elseif ($issues -match "Service account|Old password") { "Medium" } else { "Low" }
                    }
                    
                    $groupAnalysis.SecurityIssues += $securityIssue
                    $script:SecurityIssues += $securityIssue
                }
                
            } catch {
                Write-Warning "Failed to get details for member '$($member.SamAccountName)' in group '$GroupName': $_"
                
                # Add basic information even if detailed query fails
                $memberInfo = [PSCustomObject]@{
                    GroupName = $GroupName
                    MemberName = $member.SamAccountName
                    DisplayName = $member.Name
                    MemberType = $member.objectClass
                    Title = "Error retrieving details"
                    Department = ""
                    Description = ""
                    LastLogon = "Unknown"
                    DaysSinceLogon = "Unknown"
                    PasswordLastSet = "Unknown"
                    PasswordAge = "Unknown"
                    AccountEnabled = "Unknown"
                    IsServiceAccount = $false
                    Created = "Unknown"
                    ExpirationDate = "Unknown"
                    DistinguishedName = $member.DistinguishedName
                }
                
                $groupAnalysis.Members += $memberInfo
            }
        }
        
        return $groupAnalysis
        
    } catch {
        Write-Warning "Group '$GroupName' not found or inaccessible: $_"
        return $null
    }
}

# Function to compare with baseline
function Compare-WithBaseline {
    param([string]$BaselineFile, [array]$CurrentResults)
    
    if (-not (Test-Path $BaselineFile)) {
        Write-ColorOutput "Baseline file not found. Creating new baseline..." -Color "Yellow"
        return @()
    }
    
    try {
        $baseline = Import-Clixml -Path $BaselineFile
        $changes = @()
        
        Write-ColorOutput "Comparing current audit with baseline..." -Color "Cyan"
        
        # Compare each group
        foreach ($currentGroup in $CurrentResults) {
            $baselineGroup = $baseline | Where-Object { $_.GroupName -eq $currentGroup.GroupName }
            
            if (-not $baselineGroup) {
                $changes += [PSCustomObject]@{
                    ChangeType = "New Group"
                    GroupName = $currentGroup.GroupName
                    Member = ""
                    Details = "Group was not in baseline"
                    Timestamp = Get-Date
                }
                continue
            }
            
            # Compare members
            $currentMembers = $currentGroup.Members | Select-Object -ExpandProperty MemberName
            $baselineMembers = $baselineGroup.Members | Select-Object -ExpandProperty MemberName
            
            # Find new members
            $newMembers = $currentMembers | Where-Object { $_ -notin $baselineMembers }
            foreach ($newMember in $newMembers) {
                $memberDetails = $currentGroup.Members | Where-Object { $_.MemberName -eq $newMember }
                $changes += [PSCustomObject]@{
                    ChangeType = "Member Added"
                    GroupName = $currentGroup.GroupName
                    Member = $newMember
                    Details = "User type: $($memberDetails.MemberType), Display: $($memberDetails.DisplayName)"
                    Timestamp = Get-Date
                }
            }
            
            # Find removed members
            $removedMembers = $baselineMembers | Where-Object { $_ -notin $currentMembers }
            foreach ($removedMember in $removedMembers) {
                $changes += [PSCustomObject]@{
                    ChangeType = "Member Removed"
                    GroupName = $currentGroup.GroupName
                    Member = $removedMember
                    Details = "Member no longer in group"
                    Timestamp = Get-Date
                }
            }
        }
        
        # Check for removed groups
        foreach ($baselineGroup in $baseline) {
            $currentGroup = $CurrentResults | Where-Object { $_.GroupName -eq $baselineGroup.GroupName }
            if (-not $currentGroup) {
                $changes += [PSCustomObject]@{
                    ChangeType = "Group Removed"
                    GroupName = $baselineGroup.GroupName
                    Member = ""
                    Details = "Group no longer exists or is inaccessible"
                    Timestamp = Get-Date
                }
            }
        }
        
        Write-ColorOutput "Found $($changes.Count) changes since baseline." -Color "Yellow"
        return $changes
        
    } catch {
        Write-Warning "Failed to compare with baseline: $_"
        return @()
    }
}

# Function to generate HTML report
function New-HTMLAuditReport {
    param(
        [array]$AuditResults,
        [array]$SecurityIssues,
        [array]$Changes,
        [hashtable]$Statistics,
        [string]$FilePath
    )

    # Calculate additional statistics
    $totalIssues = $SecurityIssues.Count
    $highSeverityIssues = ($SecurityIssues | Where-Object { $_.Severity -eq "High" }).Count
    $mediumSeverityIssues = ($SecurityIssues | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowSeverityIssues = ($SecurityIssues | Where-Object { $_.Severity -eq "Low" }).Count

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Privileged Group Membership Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #0078d4; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { background-color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .section { background-color: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .section h3 { color: #0078d4; border-bottom: 2px solid #0078d4; padding-bottom: 5px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0; }
        .stat-box { background-color: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-number { font-size: 24px; font-weight: bold; color: #0078d4; }
        .stat-label { font-size: 14px; color: #666; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
        th { background-color: #f2f2f2; font-weight: bold; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .severity-high { color: #dc3545; font-weight: bold; }
        .severity-medium { color: #fd7e14; font-weight: bold; }
        .severity-low { color: #ffc107; font-weight: bold; }
        .change-added { color: #28a745; font-weight: bold; }
        .change-removed { color: #dc3545; font-weight: bold; }
        .change-new { color: #17a2b8; font-weight: bold; }
        .timestamp { font-size: 0.9em; color: #666; }
        .collapsible { background-color: #eee; color: #444; cursor: pointer; padding: 18px; width: 100%; border: none; text-align: left; outline: none; font-size: 15px; }
        .collapsible:hover { background-color: #ccc; }
        .content { padding: 0 18px; display: none; overflow: hidden; background-color: #f1f1f1; }
        .alert { padding: 15px; margin: 10px 0; border-radius: 5px; }
        .alert-danger { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .alert-warning { background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
        .alert-info { background-color: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Privileged Group Membership Audit Report</h1>
        <p>Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p>Domain: $(if ($Domain) { $Domain } else { $env:USERDNSDOMAIN })</p>
        <p>Report Duration: $([math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 2)) seconds</p>
    </div>

    <div class="summary">
        <h2>📊 Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-box">
                <div class="stat-number">$($Statistics.TotalGroups)</div>
                <div class="stat-label">Groups Audited</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">$($Statistics.TotalMembers)</div>
                <div class="stat-label">Total Members</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">$($Statistics.TotalUsers)</div>
                <div class="stat-label">User Accounts</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">$totalIssues</div>
                <div class="stat-label">Security Issues</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">$($Statistics.InactiveAccounts)</div>
                <div class="stat-label">Inactive Accounts</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">$($Changes.Count)</div>
                <div class="stat-label">Recent Changes</div>
            </div>
        </div>
    </div>
"@

    if ($totalIssues -gt 0) {
        $html += @"
    <div class="section">
        <h3>🚨 Security Issues Summary</h3>
        <div class="stats-grid">
            <div class="stat-box">
                <div class="stat-number severity-high">$highSeverityIssues</div>
                <div class="stat-label">High Severity</div>
            </div>
            <div class="stat-box">
                <div class="stat-number severity-medium">$mediumSeverityIssues</div>
                <div class="stat-label">Medium Severity</div>
            </div>
            <div class="stat-box">
                <div class="stat-number severity-low">$lowSeverityIssues</div>
                <div class="stat-label">Low Severity</div>
            </div>
        </div>
        
        <table>
            <tr><th>Group</th><th>Member</th><th>Type</th><th>Issues</th><th>Severity</th></tr>
"@
        foreach ($issue in ($SecurityIssues | Sort-Object Severity, GroupName)) {
            $severityClass = "severity-" + $issue.Severity.ToLower()
            $html += "<tr><td>$($issue.GroupName)</td><td>$($issue.MemberName)</td><td>$($issue.MemberType)</td><td>$($issue.Issues)</td><td class='$severityClass'>$($issue.Severity)</td></tr>"
        }
        $html += "</table></div>"
    }

    if ($Changes.Count -gt 0) {
        $html += @"
    <div class="section">
        <h3>📝 Recent Changes</h3>
        <table>
            <tr><th>Change Type</th><th>Group</th><th>Member</th><th>Details</th><th>Timestamp</th></tr>
"@
        foreach ($change in ($Changes | Sort-Object Timestamp -Descending)) {
            $changeClass = switch ($change.ChangeType) {
                "Member Added" { "change-added" }
                "Member Removed" { "change-removed" }
                default { "change-new" }
            }
            $html += "<tr><td class='$changeClass'>$($change.ChangeType)</td><td>$($change.GroupName)</td><td>$($change.Member)</td><td>$($change.Details)</td><td class='timestamp'>$($change.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>"
        }
        $html += "</table></div>"
    }

    # Group membership details
    $html += @"
    <div class="section">
        <h3>👥 Detailed Group Memberships</h3>
"@

    foreach ($groupResult in ($AuditResults | Sort-Object GroupName)) {
        $issueCount = ($SecurityIssues | Where-Object { $_.GroupName -eq $groupResult.GroupName }).Count
        $issueIndicator = if ($issueCount -gt 0) { " ⚠️ ($issueCount issues)" } else { "" }
        
        $html += @"
        <button class="collapsible">$($groupResult.GroupName) ($($groupResult.MemberCount) members)$issueIndicator</button>
        <div class="content">
            <p><strong>Description:</strong> $($groupResult.Description)</p>
            <p><strong>Created:</strong> $($groupResult.Created)</p>
            <table>
                <tr><th>Member</th><th>Display Name</th><th>Type</th><th>Title</th><th>Last Logon</th><th>Enabled</th><th>Issues</th></tr>
"@
        
        foreach ($member in ($groupResult.Members | Sort-Object MemberName)) {
            $memberIssues = ($SecurityIssues | Where-Object { $_.GroupName -eq $groupResult.GroupName -and $_.MemberName -eq $member.MemberName }).Issues
            $issuesDisplay = if ($memberIssues) { $memberIssues } else { "None" }
            
            $html += "<tr><td>$($member.MemberName)</td><td>$($member.DisplayName)</td><td>$($member.MemberType)</td><td>$($member.Title)</td><td>$($member.LastLogon)</td><td>$($member.AccountEnabled)</td><td>$issuesDisplay</td></tr>"
        }
        
        $html += "</table></div>"
    }

    $html += @"
    </div>

    <script>
    var coll = document.getElementsByClassName("collapsible");
    var i;
    for (i = 0; i < coll.length; i++) {
        coll[i].addEventListener("click", function() {
            this.classList.toggle("active");
            var content = this.nextElementSibling;
            if (content.style.display === "block") {
                content.style.display = "none";
            } else {
                content.style.display = "block";
            }
        });
    }
    </script>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $FilePath -Encoding UTF8
        Write-ColorOutput "HTML audit report saved to: $FilePath" -Color "Green"
    } catch {
        Write-ColorOutput "Failed to save HTML audit report: $($_.Exception.Message)" -Color "Red"
    }
}

# Main script execution
try {
    Write-ColorOutput "🛡️ Privileged Group Membership Audit" -Color "Cyan"
    Write-ColorOutput "====================================" -Color "Cyan"
    Write-ColorOutput "Domain: $(if ($Domain) { $Domain } else { 'Current Domain' })" -Color "White"
    Write-ColorOutput "Groups to audit: $($AllGroupsToAudit.Count)" -Color "White"
    Write-ColorOutput "Include nested groups: $IncludeNestedGroups" -Color "White"
    Write-ColorOutput "Exclude service accounts: $ExcludeServiceAccounts" -Color "White"
    Write-ColorOutput "Started at: $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color "White"
    Write-ColorOutput ""

    # Build parameters for AD cmdlets
    $adParams = @{
    }
    if ($Domain) {
        try {
            Get-ADDomain -Identity $Domain -ErrorAction Stop | Out-Null
            $adParams.Server = $Domain
            Write-ColorOutput "✓ Successfully connected to domain: $Domain" -Color "Green"
        } catch {
            Write-Error "Failed to connect to domain '$Domain': $_"
            exit 1
        }
    }

    if ($Credential) {
        $adParams.Credential = $Credential
        Write-ColorOutput "✓ Using provided credentials" -Color "Green"
    }

    # Audit each privileged group
    foreach ($groupName in $AllGroupsToAudit) {
        $groupAnalysis = Get-GroupMembershipAnalysis -GroupName $groupName -ADParams $adParams
        if ($groupAnalysis) {
            $script:AuditResults += $groupAnalysis
        }
    }

    # Load baseline and compare if requested
    if ($AlertOnChanges) {
        if ($BaselineFile) {
            $script:Changes = Compare-WithBaseline -BaselineFile $BaselineFile -CurrentResults $script:AuditResults
        } else {
            Write-ColorOutput "No baseline file specified for change detection." -Color "Yellow"
        }
    }

    # Identify users in multiple admin groups
    $userGroupCounts = @{
    }
    foreach ($result in $script:AuditResults) {
        foreach ($member in $result.Members) {
            if ($member.MemberType -eq "user") {
                if ($userGroupCounts.ContainsKey($member.MemberName)) {
                    $userGroupCounts[$member.MemberName]++
                } else {
                    $userGroupCounts[$member.MemberName] = 1
                }
            }
        }
    }
    $script:Statistics.MultipleGroupMemberships = ($userGroupCounts.GetEnumerator() | Where-Object { $_.Value -gt 1 }).Count

    # Display summary
    $duration = [math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 2)
    
    Write-ColorOutput "`n📊 Audit Summary" -Color "Cyan"
    Write-ColorOutput "=================" -Color "Cyan"
    Write-ColorOutput "Groups audited: $($script:Statistics.TotalGroups)" -Color "White"
    Write-ColorOutput "Total members: $($script:Statistics.TotalMembers)" -Color "White"
    Write-ColorOutput "User accounts: $($script:Statistics.TotalUsers)" -Color "White"
    Write-ColorOutput "Computer accounts: $($script:Statistics.TotalComputers)" -Color "White"
    Write-ColorOutput "Service accounts: $($script:Statistics.TotalServiceAccounts)" -Color "White"
    Write-ColorOutput "Security issues found: " -Color "White" -NoNewline
    Write-ColorOutput "$($script:SecurityIssues.Count)" -Color "Red"
    Write-ColorOutput "Recent changes: $($script:Changes.Count)" -Color "White"
    Write-ColorOutput "Users in multiple groups: $($script:Statistics.MultipleGroupMemberships)" -Color "White"
    Write-ColorOutput "Audit duration: $duration seconds" -Color "White"

    if ($script:SecurityIssues.Count -gt 0) {
        Write-ColorOutput "`n🚨 Top Security Issues:" -Color "Red"
        $script:SecurityIssues | Sort-Object Severity, GroupName | Select-Object -First 10 | ForEach-Object {
            Write-ColorOutput "  [$($_.Severity)] $($_.GroupName) - $($_.MemberName): $($_.Issues)" -Color "Yellow"
        }
    }

    if ($script:Changes.Count -gt 0) {
        Write-ColorOutput "`n📝 Recent Changes:" -Color "Yellow"
        $script:Changes | Sort-Object Timestamp -Descending | Select-Object -First 10 | ForEach-Object {
            Write-ColorOutput "  $($_.ChangeType): $($_.GroupName) - $($_.Member)" -Color "Cyan"
        }
    }

    if ($script:Statistics.MultipleGroupMemberships -gt 0) {
        Write-ColorOutput "`n👥 Users in Multiple Admin Groups:" -Color "Yellow"
        $userGroupCounts.GetEnumerator() | Where-Object { $_.Value -gt 1 } | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object {
            Write-ColorOutput "  $($_.Key): $($_.Value) groups" -Color "Cyan"
        }
    }

    # Generate reports if OutputPath is specified
    if ($OutputPath) {
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }

        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $computerName = $env:COMPUTERNAME
        
        # CSV Report for all members
        $csvPath = Join-Path -Path $OutputPath -ChildPath "PrivilegedGroups-Members-$computerName-$timestamp.csv"
        try {
            $allMembers = @()
            foreach ($result in $script:AuditResults) {
                $allMembers += $result.Members
            }
            $allMembers | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-ColorOutput "CSV members report saved to: $csvPath" -Color "Green"
        } catch {
            Write-ColorOutput "Failed to save CSV members report: $($_.Exception.Message)" -Color "Red"
        }

        # CSV Report for security issues
        if ($script:SecurityIssues.Count -gt 0) {
            $issuesCsvPath = Join-Path -Path $OutputPath -ChildPath "PrivilegedGroups-Issues-$computerName-$timestamp.csv"
            try {
                $script:SecurityIssues | Export-Csv -Path $issuesCsvPath -NoTypeInformation -Encoding UTF8
                Write-ColorOutput "CSV issues report saved to: $issuesCsvPath" -Color "Green"
            } catch {
                Write-ColorOutput "Failed to save CSV issues report: $($_.Exception.Message)" -Color "Red"
            }
        }

        # CSV Report for changes if any exist
        if ($script:Changes.Count -gt 0) {
            $changesCsvPath = Join-Path -Path $OutputPath -ChildPath "PrivilegedGroups-Changes-$computerName-$timestamp.csv"
            try {
                $script:Changes | Export-Csv -Path $changesCsvPath -NoTypeInformation -Encoding UTF8
                Write-ColorOutput "CSV changes report saved to: $changesCsvPath" -Color "Green"
            } catch {
                Write-ColorOutput "Failed to save CSV changes report: $($_.Exception.Message)" -Color "Red"
            }
        }

        # HTML Report
        $htmlPath = Join-Path -Path $OutputPath -ChildPath "PrivilegedGroups-Audit-$computerName-$timestamp.html"
        New-HTMLAuditReport -AuditResults $script:AuditResults -SecurityIssues $script:SecurityIssues -Changes $script:Changes -Statistics $script:Statistics -FilePath $htmlPath

        # Create or update baseline
        $baselinePath = if ($BaselineFile) { $BaselineFile } else { Join-Path -Path $OutputPath -ChildPath "PrivilegedGroups-Baseline.xml" }
        try {
            $script:AuditResults | Export-Clixml -Path $baselinePath
            Write-ColorOutput "Baseline saved to: $baselinePath" -Color "Green"
        } catch {
            Write-ColorOutput "Failed to save baseline: $($_.Exception.Message)" -Color "Red"
        }
    }

} catch {
    Write-ColorOutput "Script execution failed: $($_.Exception.Message)" -Color "Red"
    Write-ColorOutput $_.ScriptStackTrace -Color "Red"
    exit 1
}

Write-ColorOutput "`n✅ Privileged group audit completed successfully." -Color "Green"
Write-ColorOutput "Review the generated reports for detailed findings and recommendations." -Color "White"

if ($script:SecurityIssues.Count -gt 0) {
    Write-ColorOutput "`n⚠️  $($script:SecurityIssues.Count) security issues identified. Please review and remediate." -Color "Yellow"
    $highSeverity = ($script:SecurityIssues | Where-Object { $_.Severity -eq "High" }).Count
    if ($highSeverity -gt 0) {
        Write-ColorOutput "🚨 $highSeverity HIGH SEVERITY issues require immediate attention!" -Color "Red"
    }
}