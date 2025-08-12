param(
    [Parameter(Mandatory = $true)]
    [string]$SID
)

try {
    $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
    $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
    Write-Output $objUser.Value
} catch {
    Write-Error "Failed to translate SID '$SID' to a username. Error: $_"
}
