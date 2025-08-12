<#
.SYNOPSIS
    Tests network connectivity to on-premises and cloud services with comprehensive reporting.

.DESCRIPTION
    This script provides comprehensive network connectivity testing for enterprise environments, 
    including on-premises services, Microsoft 365, and Azure services. It can test basic connectivity,
    DNS resolution, latency measurements, and specific port connectivity. Results can be exported
    to various formats for analysis and reporting.

.PARAMETER TestType
    Specifies which set of tests to run. Valid values are:
    - "Basic": Tests internet connectivity, DNS, and basic network configuration
    - "OnPrem": Tests connectivity to on-premises services (domain controllers, file servers, etc.)
    - "M365": Tests Microsoft 365 service connectivity
    - "Azure": Tests Azure service connectivity
    - "All": Runs all test types (default)

.PARAMETER ComputerName
    Optional computer name to test connectivity from a remote machine. Requires appropriate permissions.

.PARAMETER OutputPath
    Optional path to save detailed HTML and CSV reports.

.PARAMETER IncludeDNS
    Switch parameter to include DNS resolution tests for all targets.

.PARAMETER IncludeLatency
    Switch parameter to measure and report response times for all tests.

.PARAMETER Credential
    Credential object for remote computer testing. Only used when ComputerName is specified.

.PARAMETER CustomTargets
    Optional hashtable of custom targets in format @{"Service Name" = "hostname:port"}

.PARAMETER TimeoutSeconds
    Timeout in seconds for each connectivity test. Default is 10 seconds.

.PARAMETER MaxLatencyTests
    Number of ping tests to perform for latency measurements. Default is 4.

.EXAMPLE
    .\Test-NetworkConnectivity.ps1
    Runs all connectivity tests from the local machine with default settings.

.EXAMPLE
    .\Test-NetworkConnectivity.ps1 -TestType "M365" -IncludeDNS -IncludeLatency -OutputPath "C:\Reports\"
    Tests only Microsoft 365 connectivity with DNS resolution and latency measurements, saving reports to C:\Reports.

.EXAMPLE
    .\Test-NetworkConnectivity.ps1 -TestType "OnPrem" -ComputerName "WORKSTATION01" -Credential $cred
    Tests on-premises connectivity from remote computer WORKSTATION01.

.EXAMPLE
    .\Test-NetworkConnectivity.ps1 -CustomTargets @{"Custom Service" = "server.domain.com:8080"} -TestType "Basic"
    Runs basic tests plus custom service connectivity test.

.NOTES
    Author: Haakon Wibe
    Date: Created for powershell-utilities repository
    
    This script requires PowerShell 4.0 or later for best compatibility.
    Some tests require administrative privileges for accurate results.
    
    For M365 testing, ensure that Microsoft 365 URLs and IP ranges are accessible.
    For Azure testing, verify that Azure endpoints are not blocked by firewalls.
    
    Remote testing requires WinRM to be enabled on target computers.
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "OnPrem", "M365", "Azure", "All")]
    [string]$TestType = "All",

    [Parameter(Mandatory = $false)]
    [string]$ComputerName,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [switch]$IncludeDNS,
    
    [switch]$IncludeLatency,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [hashtable]$CustomTargets = @{},

    [Parameter(Mandatory = $false)]
    [int]$TimeoutSeconds = 10,

    [Parameter(Mandatory = $false)]
    [int]$MaxLatencyTests = 4
)

# Initialize script variables
$script:TestResults = @()
$script:StartTime = Get-Date
$script:IsRemote = -not [string]::IsNullOrEmpty($ComputerName)

# Define predefined test targets
$OnPremServices = @{
    "Domain Controller (LDAP)" = "your-dc.domain.com:389"
    "Domain Controller (LDAPS)" = "your-dc.domain.com:636"
    "File Server (SMB)" = "fileserver.domain.com:445"
    "Exchange Server (HTTPS)" = "exchange.domain.com:443"
    "Print Server" = "printserver.domain.com:9100"
    "SQL Server" = "sqlserver.domain.com:1433"
    "Web Server (HTTP)" = "intranet.domain.com:80"
    "Web Server (HTTPS)" = "intranet.domain.com:443"
}

$M365Services = @{
    "Exchange Online" = "outlook.office365.com:443"
    "SharePoint Online" = "tenant.sharepoint.com:443"
    "Microsoft Teams" = "teams.microsoft.com:443"
    "OneDrive for Business" = "onedrive.live.com:443"
    "Azure AD / Entra ID" = "login.microsoftonline.com:443"
    "Office 365 Portal" = "portal.office.com:443"
    "Microsoft Graph" = "graph.microsoft.com:443"
    "Exchange Online Protection" = "protection.outlook.com:443"
    "Skype for Business Online" = "webdir.online.lync.com:443"
    "Power Platform" = "powerapps.microsoft.com:443"
}

$AzureServices = @{
    "Azure Portal" = "portal.azure.com:443"
    "Azure Storage" = "storage.azure.com:443"
    "Azure AD Graph" = "graph.windows.net:443"
    "Azure Resource Manager" = "management.azure.com:443"
    "Azure Key Vault" = "vault.azure.net:443"
    "Azure SQL Database" = "database.windows.net:1433"
    "Azure Service Bus" = "servicebus.windows.net:443"
    "Azure Event Hubs" = "eventhubs.azure.net:443"
    "Microsoft Intune" = "manage.microsoft.com:443"
    "Windows Update" = "update.microsoft.com:443"
}

$BasicServices = @{
    "Google DNS" = "8.8.8.8:53"
    "Cloudflare DNS" = "1.1.1.1:53"
    "Microsoft DNS" = "4.2.2.1:53"
    "Internet Connectivity" = "www.microsoft.com:443"
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

# Helper function to test network connectivity
function Test-NetworkTarget {
    param(
        [string]$TargetName,
        [string]$TargetAddress,
        [int]$Port,
        [string]$Category
    )

    $testResult = [PSCustomObject]@{
        Timestamp = Get-Date
        Category = $Category
        TargetName = $TargetName
        TargetAddress = $TargetAddress
        Port = $Port
        Connected = $false
        ResponseTime = $null
        DNSResolved = $null
        DNSTime = $null
        Error = $null
        RemoteComputer = if ($script:IsRemote) { $ComputerName } else { $env:COMPUTERNAME }
    }

    try {
        Write-ColorOutput "Testing $TargetName ($TargetAddress`:$Port)... " -Color "Yellow" -NoNewline

        # DNS Resolution Test
        if ($IncludeDNS) {
            $dnsStart = Get-Date
            try {
                $dnsResult = [System.Net.Dns]::GetHostAddresses($TargetAddress)
                $testResult.DNSResolved = $true
                $testResult.DNSTime = [math]::Round(((Get-Date) - $dnsStart).TotalMilliseconds, 2)
            } catch {
                $testResult.DNSResolved = $false
                $testResult.Error = "DNS Resolution Failed: $($_.Exception.Message)"
                Write-ColorOutput "DNS FAILED" -Color "Red"
                return $testResult
            }
        }

        # Connectivity Test
        if ($script:IsRemote -and $Credential) {
            $scriptBlock = {
                param($Target, $Port, $Timeout)
                Test-NetConnection -ComputerName $Target -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            }
            $connectResult = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock -ArgumentList $TargetAddress, $Port, $TimeoutSeconds -ErrorAction Stop
        } elseif ($script:IsRemote) {
            $scriptBlock = {
                param($Target, $Port, $Timeout)
                Test-NetConnection -ComputerName $Target -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            }
            $connectResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $TargetAddress, $Port, $TimeoutSeconds -ErrorAction Stop
        } else {
            $connectResult = Test-NetConnection -ComputerName $TargetAddress -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
        }

        $testResult.Connected = $connectResult

        # Latency Test
        if ($IncludeLatency -and $connectResult) {
            $pingResults = @()
            for ($i = 1; $i -le $MaxLatencyTests; $i++) {
                try {
                    $ping = Test-Connection -ComputerName $TargetAddress -Count 1 -Quiet -TimeoutSeconds $TimeoutSeconds -ErrorAction Stop
                    if ($ping) {
                        $pingTest = Test-Connection -ComputerName $TargetAddress -Count 1 -TimeoutSeconds $TimeoutSeconds -ErrorAction Stop
                        if ($pingTest.ResponseTime -ne $null) {
                            $pingResults += $pingTest.ResponseTime
                        }
                    }
                } catch {
                    # Ping failed, but connection might still work for the specific port
                    continue
                }
            }
            
            if ($pingResults.Count -gt 0) {
                $testResult.ResponseTime = [math]::Round(($pingResults | Measure-Object -Average).Average, 2)
            }
        }

        if ($testResult.Connected) {
            $statusText = "SUCCESS"
            if ($testResult.ResponseTime -ne $null) {
                $statusText += " ($($testResult.ResponseTime)ms)"
            }
            Write-ColorOutput $statusText -Color "Green"
        } else {
            Write-ColorOutput "FAILED" -Color "Red"
            $testResult.Error = "Connection failed"
        }

    } catch {
        $testResult.Error = $_.Exception.Message
        Write-ColorOutput "ERROR: $($_.Exception.Message)" -Color "Red"
    }

    return $testResult
}

# Function to test basic network configuration
function Test-BasicNetworkConfig {
    Write-ColorOutput "`n=== Basic Network Configuration Tests ===" -Color "Cyan"
    
    $configResults = @()

    # Test network adapters
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        $configResults += [PSCustomObject]@{
            Test = "Network Adapters"
            Status = if ($adapters.Count -gt 0) { "PASS" } else { "FAIL" }
            Details = "Active adapters: $($adapters.Count)"
            Category = "Network Configuration"
        }
        Write-ColorOutput "Network Adapters: " -Color "Yellow" -NoNewline
        Write-ColorOutput "$($adapters.Count) active adapter(s)" -Color "Green"
    } catch {
        Write-ColorOutput "Network Adapters: ERROR - $($_.Exception.Message)" -Color "Red"
    }

    # Test default gateway
    try {
        $gateway = Get-NetRoute | Where-Object { $_.DestinationPrefix -eq "0.0.0.0/0" } | Select-Object -First 1
        if ($gateway) {
            $gatewayTest = Test-Connection -ComputerName $gateway.NextHop -Count 1 -Quiet -TimeoutSeconds 5 -ErrorAction Stop
            $configResults += [PSCustomObject]@{
                Test = "Default Gateway"
                Status = if ($gatewayTest) { "PASS" } else { "FAIL" }
                Details = "Gateway: $($gateway.NextHop)"
                Category = "Network Configuration"
            }
            Write-ColorOutput "Default Gateway ($($gateway.NextHop)): " -Color "Yellow" -NoNewline
            Write-ColorOutput $(if ($gatewayTest) { "REACHABLE" } else { "UNREACHABLE" }) -Color $(if ($gatewayTest) { "Green" } else { "Red" })
        }
    } catch {
        Write-ColorOutput "Default Gateway: ERROR - $($_.Exception.Message)" -Color "Red"
    }

    # Test DNS configuration
    try {
        $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 }
        $configResults += [PSCustomObject]@{
            Test = "DNS Configuration"
            Status = if ($dnsServers.Count -gt 0) { "PASS" } else { "FAIL" }
            Details = "DNS servers configured: $($dnsServers.Count)"
            Category = "Network Configuration"
        }
        Write-ColorOutput "DNS Servers: " -Color "Yellow" -NoNewline
        Write-ColorOutput "$($dnsServers.Count) configured" -Color "Green"
    } catch {
        Write-ColorOutput "DNS Servers: ERROR - $($_.Exception.Message)" -Color "Red"
    }

    # Test Windows Firewall
    try {
        $firewallProfiles = Get-NetFirewallProfile
        $activeProfiles = $firewallProfiles | Where-Object { $_.Enabled -eq $true }
        $configResults += [PSCustomObject]@{
            Test = "Windows Firewall"
            Status = "INFO"
            Details = "Active profiles: $($activeProfiles.Count)/3"
            Category = "Network Configuration"
        }
        Write-ColorOutput "Windows Firewall: " -Color "Yellow" -NoNewline
        Write-ColorOutput "$($activeProfiles.Count) of 3 profiles enabled" -Color "Cyan"
    } catch {
        Write-ColorOutput "Windows Firewall: ERROR - $($_.Exception.Message)" -Color "Red"
    }

    return $configResults
}

# Function to generate HTML report
function New-HTMLReport {
    param(
        [array]$Results,
        [array]$ConfigResults,
        [string]$FilePath
    )

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Network Connectivity Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #0078d4; color: white; padding: 15px; border-radius: 5px; }
        .summary { background-color: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 5px; }
        .category { margin: 20px 0; }
        .category h3 { color: #0078d4; border-bottom: 2px solid #0078d4; padding-bottom: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .success { color: #28a745; font-weight: bold; }
        .failure { color: #dc3545; font-weight: bold; }
        .info { color: #17a2b8; font-weight: bold; }
        .error { color: #dc3545; background-color: #f8d7da; }
        .timestamp { font-size: 0.9em; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Network Connectivity Test Report</h1>
        <p>Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p>Test Type: $TestType</p>
        <p>Source Computer: $(if ($script:IsRemote) { $ComputerName } else { $env:COMPUTERNAME })</p>
    </div>

    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Tests:</strong> $($Results.Count)</p>
        <p><strong>Successful:</strong> <span class="success">$($Results | Where-Object { $_.Connected -eq $true } | Measure-Object | Select-Object -ExpandProperty Count)</span></p>
        <p><strong>Failed:</strong> <span class="failure">$($Results | Where-Object { $_.Connected -eq $false } | Measure-Object | Select-Object -ExpandProperty Count)</span></p>
        <p><strong>Test Duration:</strong> $([math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 2)) seconds</p>
    </div>
"@

    # Add configuration results if available
    if ($ConfigResults.Count -gt 0) {
        $html += @"
    <div class="category">
        <h3>Network Configuration</h3>
        <table>
            <tr><th>Test</th><th>Status</th><th>Details</th></tr>
"@
        foreach ($config in $ConfigResults) {
            $statusClass = switch ($config.Status) {
                "PASS" { "success" }
                "FAIL" { "failure" }
                default { "info" }
            }
            $html += "<tr><td>$($config.Test)</td><td class='$statusClass'>$($config.Status)</td><td>$($config.Details)</td></tr>"
        }
        $html += "</table></div>"
    }

    # Group results by category
    $categories = $Results | Group-Object -Property Category

    foreach ($category in $categories) {
        $html += @"
    <div class="category">
        <h3>$($category.Name)</h3>
        <table>
            <tr><th>Service</th><th>Target</th><th>Port</th><th>Status</th><th>Response Time</th><th>DNS</th><th>Error</th></tr>
"@
        foreach ($result in $category.Group) {
            $statusClass = if ($result.Connected) { "success" } else { "failure" }
            $statusText = if ($result.Connected) { "SUCCESS" } else { "FAILED" }
            $responseTime = if ($result.ResponseTime -ne $null) { "$($result.ResponseTime)ms" } else { "-" }
            $dnsStatus = if ($result.DNSResolved -eq $true) { "OK" } elseif ($result.DNSResolved -eq $false) { "FAILED" } else { "-" }
            $errorText = if ($result.Error) { $result.Error } else { "-" }
            
            $html += "<tr><td>$($result.TargetName)</td><td>$($result.TargetAddress)</td><td>$($result.Port)</td><td class='$statusClass'>$statusText</td><td>$responseTime</td><td>$dnsStatus</td><td class='error'>$errorText</td></tr>"
        }
        $html += "</table></div>"
    }

    $html += @"
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $FilePath -Encoding UTF8
        Write-ColorOutput "HTML report saved to: $FilePath" -Color "Green"
    } catch {
        Write-ColorOutput "Failed to save HTML report: $($_.Exception.Message)" -Color "Red"
    }
}

# Main script execution
try {
    Write-ColorOutput "Network Connectivity Test Script" -Color "Cyan"
    Write-ColorOutput "=================================" -Color "Cyan"
    Write-ColorOutput "Test Type: $TestType" -Color "White"
    Write-ColorOutput "Target Computer: $(if ($script:IsRemote) { $ComputerName } else { 'Local Computer' })" -Color "White"
    Write-ColorOutput "Include DNS Tests: $IncludeDNS" -Color "White"
    Write-ColorOutput "Include Latency Tests: $IncludeLatency" -Color "White"
    Write-ColorOutput "Started at: $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color "White"
    Write-ColorOutput ""

    # Test basic network configuration
    $configResults = @()
    if ($TestType -eq "Basic" -or $TestType -eq "All") {
        $configResults = Test-BasicNetworkConfig
    }

    # Determine which service sets to test
    $servicesToTest = @{}
    
    switch ($TestType) {
        "Basic" { 
            $servicesToTest = $BasicServices.Clone()
        }
        "OnPrem" { 
            $servicesToTest = $OnPremServices.Clone()
        }
        "M365" { 
            $servicesToTest = $M365Services.Clone()
        }
        "Azure" { 
            $servicesToTest = $AzureServices.Clone()
        }
        "All" { 
            $BasicServices.GetEnumerator() | ForEach-Object { $servicesToTest[$_.Key] = $_.Value }
            $OnPremServices.GetEnumerator() | ForEach-Object { $servicesToTest[$_.Key] = $_.Value }
            $M365Services.GetEnumerator() | ForEach-Object { $servicesToTest[$_.Key] = $_.Value }
            $AzureServices.GetEnumerator() | ForEach-Object { $servicesToTest[$_.Key] = $_.Value }
        }
    }

    # Add custom targets if specified
    if ($CustomTargets.Count -gt 0) {
        $CustomTargets.GetEnumerator() | ForEach-Object { $servicesToTest[$_.Key] = $_.Value }
    }

    # Execute tests
    Write-ColorOutput "`n=== Connectivity Tests ===" -Color "Cyan"
    
    foreach ($service in $servicesToTest.GetEnumerator()) {
        $targetInfo = $service.Value -split ':'
        $targetAddress = $targetInfo[0]
        $port = [int]$targetInfo[1]
        
        # Determine category
        $category = "Custom"
        if ($BasicServices.ContainsKey($service.Key)) { $category = "Basic Services" }
        elseif ($OnPremServices.ContainsKey($service.Key)) { $category = "On-Premises Services" }
        elseif ($M365Services.ContainsKey($service.Key)) { $category = "Microsoft 365 Services" }
        elseif ($AzureServices.ContainsKey($service.Key)) { $category = "Azure Services" }
        
        $testResult = Test-NetworkTarget -TargetName $service.Key -TargetAddress $targetAddress -Port $port -Category $category
        $script:TestResults += $testResult
    }

    # Display summary
    $successCount = ($script:TestResults | Where-Object { $_.Connected -eq $true }).Count
    $failureCount = ($script:TestResults | Where-Object { $_.Connected -eq $false }).Count
    $totalTests = $script:TestResults.Count
    $duration = [math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 2)

    Write-ColorOutput "`n=== Test Summary ===" -Color "Cyan"
    Write-ColorOutput "Total Tests: $totalTests" -Color "White"
    Write-ColorOutput "Successful: " -Color "White" -NoNewline
    Write-ColorOutput "$successCount" -Color "Green"
    Write-ColorOutput "Failed: " -Color "White" -NoNewline
    Write-ColorOutput "$failureCount" -Color "Red"
    Write-ColorOutput "Duration: $duration seconds" -Color "White"

    if ($failureCount -gt 0) {
        Write-ColorOutput "`nFailed Tests:" -Color "Red"
        $script:TestResults | Where-Object { $_.Connected -eq $false } | ForEach-Object {
            Write-ColorOutput "  - $($_.TargetName) ($($_.TargetAddress):$($_.Port))" -Color "Red"
            if ($_.Error) {
                Write-ColorOutput "    Error: $($_.Error)" -Color "Yellow"
            }
        }
    }

    # Generate reports if OutputPath is specified
    if ($OutputPath) {
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }

        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $computerName = if ($script:IsRemote) { $ComputerName } else { $env:COMPUTERNAME }
        
        # CSV Report
        $csvPath = Join-Path -Path $OutputPath -ChildPath "NetworkConnectivity-$computerName-$timestamp.csv"
        try {
            $script:TestResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-ColorOutput "`nCSV report saved to: $csvPath" -Color "Green"
        } catch {
            Write-ColorOutput "Failed to save CSV report: $($_.Exception.Message)" -Color "Red"
        }

        # HTML Report
        $htmlPath = Join-Path -Path $OutputPath -ChildPath "NetworkConnectivity-$computerName-$timestamp.html"
        New-HTMLReport -Results $script:TestResults -ConfigResults $configResults -FilePath $htmlPath
    }

} catch {
    Write-ColorOutput "Script execution failed: $($_.Exception.Message)" -Color "Red"
    exit 1
}

Write-ColorOutput "`nNetwork connectivity testing completed." -Color "Green"