# Parameterized version with error handling
param(
    [string]$ISOPath = "C:\ISO\win10-enterprise.iso",
    [string]$VMName = "WindowsAutopilot",
    [int64]$MemoryGB = 4,
    [int64]$DiskSizeGB = 80
)

# Validation
if (-not (Get-WindowsFeature -Name Hyper-V).InstallState -eq "Installed") {
    throw "Hyper-V is not enabled"
}
if (-not (Test-Path $ISOPath)) {
    throw "ISO file not found: $ISOPath"
}

New-VMSwitch -Name AutopilotExternal -AllowManagementOS $true -NetAdapterName (Get-NetAdapter |?{$_.Status -eq "Up" -and !$_.Virtual}).Name
New-VM -Name $VMName -MemoryStartupBytes ($MemoryGB * 1GB) -BootDevice VHD -NewVHDPath ".\VMs\$VMName.vhdx" -Path .\VMData -NewVHDSizeBytes ($DiskSizeGB * 1GB) -Generation 2 -Switch AutopilotExternalWiFi
Add-VMDvdDrive -Path $ISOPath -VMName $VMName
Start-VM -VMName $VMName