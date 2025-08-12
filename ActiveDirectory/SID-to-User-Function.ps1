function Get-UsernameFromSID {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SID
    )

    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        return $objUser.Value
    } catch {
        Write-Error "Failed to translate SID '$SID' to a username. Error: $_"
    }
}

# Example usage:
$username = Get-UsernameFromSID -SID "S-1-5-32-545"
Write-Output $username
