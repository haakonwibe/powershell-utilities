# Script to move the computer object in AD to the OU supplied as a variable
# Example Command line Powershell.exe -NoProfile -Set-ExecutionPolicy bypass -file MoveToOU.ps1 "%MachineObjectOU%"

# $OU = $args[0]
$OU = "OU=Laptops,OU=Clients,OU=Company,DC=hawkweave,DC=com"

try {
    $CompDN = ([ADSISEARCHER]"sAMAccountName=$($env:COMPUTERNAME)$").FindOne().Path
    $CompObj = [ADSI]"$CompDN"
    If ($CompObj.Path -notlike "*OU=Clients,OU=Company,DC=hawkweave,DC=com")
    {
        Write-Host "Computer is not a Laptop device"
        $CompObj.psbase.MoveTo([ADSI]"LDAP://$($OU)")
    }
    
}
catch {
    $_.Exception.Message ; Exit 1
}