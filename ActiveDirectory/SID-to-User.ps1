$objSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-545") 
$objUser = $objSID.Translate([System.Security.Principal.NTAccount]) 
$objUser.Value