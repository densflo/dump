# Define an array of user accounts
$users = @("d_flores", "m_bindoy", "j_estropigan","r_binas")

# Define an empty array to store the security groups
$groups = @()

# Loop through each user account
foreach ($user in $users) {
    # Get the security groups for the user
    $userGroups = Get-ADPrincipalGroupMembership $user

    # Add the security groups to the array
    foreach ($group in $userGroups) {
        $groups += $group
    }
}

# Find the common security groups
$commonGroups = $groups | Group-Object -Property Name | Where-Object {$_.Count -eq $users.Count} | Select-Object -ExpandProperty Name

# Loop through each common security group and get its name and description
$groupInfo = foreach ($group in $commonGroups) {
    $groupObject = Get-ADGroup $group
    [PSCustomObject]@{
        GroupName = $groupObject.Name
        GroupDescription = $groupObject.Description
    }
}

# Export the group info to a CSV file
$groupInfo | Export-Csv -Path "CommonSecurityGroups_normalAccount.csv" -NoTypeInformation
