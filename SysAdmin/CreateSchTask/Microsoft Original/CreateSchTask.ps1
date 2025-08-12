# Specify the command and argument
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-ExecutionPolicy Bypass -File C:\Intune\FirewallRule.ps1'

### Use Powershell instead
# $action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
#
#   -Argument '-NoProfile -WindowStyle Hidden -command "& {get-eventlog -logname Application -After ((get-date).AddDays(-1)) | Export-Csv -Path c:\fso\applog.csv -Force -NoTypeInformation}"'
###

# Set the trigger to be at any user logon
$trigger =  New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)

# Specifies that Task Scheduler uses the Local Service account to run tasks, and that the Local Service account uses the Service Account logon. The command assigns the **ScheduledTaskPrincipal** object to the $STPrin variable.
$STPrin = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

# Create the scheduled task
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "TeamsFW" -Description "Register Teams Firewall rules" -Principal $STPrin

## Delete the scheduled Task
# Unregister-ScheduledTask -TaskName StartCMD -Confirm:$False
##