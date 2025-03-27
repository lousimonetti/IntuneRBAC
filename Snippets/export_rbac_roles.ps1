# Step 1: Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementRBAC.Read.All"

# Step 2: Function to Fetch Permissions
function Get-Roles {
    param($Uri)
    $response = Invoke-MgGraphRequest -Uri $Uri -Method GET

    # Process and return the response values for all roles
    foreach ($role in $response.value) {
        [PSCustomObject]@{
            DisplayName = $role.displayName
            IsBuiltIn   = $role.isBuiltIn
            Description = $role.description
            ScopeTag    = $role.roleScopeTagIds
        }
    }

    # Recursively call for next link if available
    if ($response.'@odata.nextLink') {
        Get-Roles -Uri $response.'@odata.nextLink'
    }
}

# Fetch Permissions
$Uri = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions"
Get-Roles -Uri $rolesUri

# Out-GridView -PassThru -Title "Select Permissions to Export" 
#| Export-Csv -Path "C:\Users\UgurKoc\Downloads\permissions.csv" -NoTypeInformation 