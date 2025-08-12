# PowerShell Utilities 🛠️

A comprehensive collection of enterprise PowerShell scripts and utilities for Active Directory, Exchange Online, migration tasks, and system administration.

## Overview

Professional-grade PowerShell scripts designed for Windows enterprise environments. These utilities cover common administrative tasks including user management, account maintenance, migration planning, Exchange connectivity, and system automation. All scripts include comprehensive error handling, parameter validation, and detailed documentation.

## Tools

### **[ActiveDirectory](./ActiveDirectory/)**
Active Directory management and user administration utilities.

**Scripts:**
- **Get-StaleUsers.ps1** - Finds inactive users based on last logon date with multi-DC support
- **Find-LockedAccounts.ps1** - Discovers and optionally unlocks locked user accounts
- **MoveToOU_v1.ps1** - Moves computer objects to specific organizational units
- **SID-to-User utilities** - Convert Windows SIDs to usernames (multiple versions)

**Use cases**: User cleanup, account management, security auditing, organizational unit management

### **[Exchange](./Exchange/)**
Exchange Online management and connectivity tools.

**Scripts:**
- **Connect-Exchange.ps1** - Modern authentication connection to Exchange Online with MFA support
- **ActiveSync_Device_Statistics.ps1** - Gather ActiveSync device statistics and reporting

**Use cases**: Exchange administration, device management, connectivity automation

### **[Migration](./Migration/)**
Data migration planning and analysis utilities.

**Scripts:**
- **Gather-HomeDrive-Statistics.ps1** - Analyzes user home directory sizes for migration planning

**Use cases**: Migration assessment, storage planning, capacity analysis

### **[Security](./Security/)**
Security and compliance management tools.

**Scripts:**
- **GPO-Server-Match.ps1** - Group Policy Object and server matching utilities

**Use cases**: Security auditing, compliance reporting, policy management

### **[SysAdmin](./SysAdmin/)**
System administration and automation tools.

**Scripts:**
- **HyperV-AutoPilot-VM.ps1** - Automated Hyper-V VM creation for Windows AutoPilot
- **[CreateSchTask](./SysAdmin/CreateSchTask/)** - Teams firewall rule deployment with scheduled task automation

**Use cases**: VM provisioning, device management, automated deployments

### **[Third-Party](./Third-Party/)**
External utility integrations and community scripts.

**Scripts:**
- **Get-WindowsAutoPilotInfo.ps1** - Windows AutoPilot hardware information gathering
- **Custom_Teams_Background.ps1** - Microsoft Teams customization utilities

**Use cases**: Device enrollment, hardware inventory, application customization

## Usage

- Each script includes comprehensive help documentation with examples
- Scripts support both PowerShell 5.1 and PowerShell 7+
- Many scripts include CSV export functionality for reporting
- All scripts follow consistent parameter naming and error handling patterns
- Run scripts with appropriate permissions (many require elevation)

## Requirements

- **Windows 10/11** or Windows Server 2016+
- **PowerShell 5.1** or later (PowerShell 7+ supported)
- **Active Directory PowerShell Module** (for AD scripts)
- **Exchange Online Management Module** (for Exchange scripts)
- **Administrative privileges** required for most scripts
- **RSAT tools** installed for Active Directory management

## Installation

1. Download or clone the repository:
git clone https://github.com/haakonwibe/powershell-utilities.git
2. Navigate to the specific script folder you need
3. Review the script documentation and examples
4. Ensure required modules are installed
5. Run with appropriate permissions (Run as Administrator when needed)
6. Test scripts in a non-production environment first

## Key Features

- **Enterprise-Ready**: Comprehensive error handling and logging
- **Multi-Environment**: Support for multiple domains and credentials
- **Export Capabilities**: CSV export functionality for reporting and analysis
- **PowerShell Compatibility**: Works with both Windows PowerShell and PowerShell Core
- **Professional Documentation**: Detailed help with examples and parameter descriptions
- **Modular Design**: Each utility is self-contained and can be used independently

## Examples

### Find Inactive Users

Find users inactive for 90+ days
.\ActiveDirectory\Get-StaleUsers.ps1 -DaysInactive 90
Export results to CSV
.\ActiveDirectory\Get-StaleUsers.ps1 -DaysInactive 60 -ExportPath "C:\Reports\StaleUsers.csv"


### Manage Locked Accounts

Find locked accounts
.\ActiveDirectory\Find-LockedAccounts.ps1
Find and unlock with confirmation
.\ActiveDirectory\Find-LockedAccounts.ps1 -UnlockAccounts


### Connect to Exchange Online
Connect with MFA
.\Exchange\Connect-Exchange.ps1 -Username admin@domain.com -UseMFA


## Contributing

These utilities are actively maintained and used in enterprise environments. Contributions, suggestions, and issue reports are welcome.

## License

MIT License - Free to use, modify, and distribute.

---

*Enterprise PowerShell utilities by [@haakonwibe](https://github.com/haakonwibe)*