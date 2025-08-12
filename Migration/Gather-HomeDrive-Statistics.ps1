# Script: Gather-HomeDrive-Statistics.ps1
# Description: This script iterates through a group of users in Active Directory, retrieves their HomeDrive attribute,
#              determines the file share location, and calculates the space consumed by each user.

# Import Active Directory module
Import-Module ActiveDirectory

# Define the output array
$results = @()

# Get all users from a specific Organizational Unit (OU)
# Replace 'OU=Users,DC=example,DC=com' with your target OU
$users = Get-ADUser -Filter * -SearchBase "OU=Users,DC=example,DC=com" -Property HomeDirectory

foreach ($user in $users) {
    # Skip users without a HomeDirectory attribute
    if (-not $user.HomeDirectory) {
        continue
    }

    $homeDirectory = $user.HomeDirectory

    # Check if the HomeDirectory path exists
    if (Test-Path -Path $homeDirectory) {
        # Get the size of the HomeDirectory
        $size = Get-ChildItem -Path $homeDirectory -Recurse -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue

        $totalSizeMB = [math]::Round(($size.Sum / 1MB), 2)

        # Add the result to the output array
        $results += [PSCustomObject]@{
            UserName       = $user.SamAccountName
            HomeDirectory  = $homeDirectory
            TotalSizeInMB  = $totalSizeMB
        }
    } else {
        # Add a result for users with an invalid HomeDirectory path
        $results += [PSCustomObject]@{
            UserName       = $user.SamAccountName
            HomeDirectory  = $homeDirectory
            TotalSizeInMB  = "Path Not Found"
        }
    }
}

# Output the results in a table format
$results | Sort-Object -Property UserName | Format-Table -AutoSize

# Optionally, export the results to a CSV file
# $results | Export-Csv -Path "HomeDriveStatistics.csv" -NoTypeInformation -Encoding UTF8