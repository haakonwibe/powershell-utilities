# Teams Firewall Rule Deployment Scripts

## Overview

These PowerShell scripts are designed to automate the creation of inbound firewall rules for Microsoft Teams for all user profiles on a system. Due to permissions requirements, the firewall rules must be created with elevated privileges, and in the context of the user profiles where Teams is installed.

## Scripts

### 1. Create Scheduled Task Script (`CreateSchTask.ps1`)

This script creates a scheduled task that runs a specified PowerShell script with elevated permissions.

#### Parameters

- **`$ScriptPath`**: *(Required)* The full path to the PowerShell script to be executed.
- **`$TaskName`**: *(Required)* The name of the scheduled task to create.
- **`$TriggerAtLogon`**: *(Optional)* A switch parameter. If specified, the task triggers at user logon.
- **`$DelayMinutes`**: *(Optional)* The delay in minutes before the task triggers (default is 1 minute).

#### Usage

```powershell
.\CreateSchTask.ps1 -ScriptPath "C:\Scripts\FirewallRule.ps1" -TaskName "TeamsFirewallRules" -TriggerAtLogon
