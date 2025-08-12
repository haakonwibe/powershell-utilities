<#
.SYNOPSIS
    Creates a scheduled task to execute a specified script with elevated permissions.

.DESCRIPTION
    This script registers a scheduled task that runs a specified PowerShell script using the SYSTEM account.
    It is designed to trigger upon user logon or at a specific time.

.PARAMETER ScriptPath
    The full path to the PowerShell script to be executed by the scheduled task.

.PARAMETER TaskName
    The name of the scheduled task to create.

.PARAMETER TriggerAtLogon
    A switch parameter. If specified, the task will trigger at any user logon. Otherwise, it triggers once after a specified delay.

.PARAMETER DelayMinutes
    The delay in minutes before the task is triggered (used when TriggerAtLogon is not specified). Default is 1 minute.

.EXAMPLE
    .\CreateSchTask.ps1 -ScriptPath "C:\Scripts\FirewallRule.ps1" -TaskName "TeamsFW" -TriggerAtLogon

.NOTES
    Author: Haakon Wibe
    Date: 05.11.2018
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptPath,

    [Parameter(Mandatory = $true)]
    [string]$TaskName,

    [switch]$TriggerAtLogon,

    [int]$DelayMinutes = 1
)

try {
    # Validate script path
    if (-not (Test-Path -Path $ScriptPath)) {
        throw "The script file '$ScriptPath' does not exist."
    }

    # Define the action to execute the script
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -File `"$ScriptPath`""

    # Define the trigger
    if ($TriggerAtLogon) {
        $trigger = New-ScheduledTaskTrigger -AtLogOn
    } else {
        $triggerTime = (Get-Date).AddMinutes($DelayMinutes)
        $trigger = New-ScheduledTaskTrigger -Once -At $triggerTime
    }

    # Define the principal (run as SYSTEM)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Register the scheduled task
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $TaskName -Description "Execute script $ScriptPath" -Principal $principal -Force

    Write-Host "Scheduled task '$TaskName' created successfully."
} catch {
    Write-Error "Failed to create scheduled task: $_"
}
