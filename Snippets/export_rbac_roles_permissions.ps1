# Step 1: Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementRBAC.Read.All"

# Step 2: Function to Fetch Permissions
function Get-RolePermissions {
    param($Uri)
    $response = Invoke-MgGraphRequest -Uri $Uri -Method GET

    # Process and return the response values for all roles
    foreach ($role in $response.value) {
        $allowedActions = @()
        foreach ($perm in $role.rolePermissions) {
            foreach ($action in $perm.resourceActions) {
                $allowedActions += $action.allowedResourceActions
            }
        }

        [PSCustomObject]@{
            DisplayName = $role.displayName
            IsBuiltIn = $role.isBuiltIn
            Description = $role.description
            ScopeTag = $role.roleScopeTagIds
            AllowedResourceActions = $allowedActions -join ', '
        }
    }

    # Recursively call for next link if available
    if ($response.'@odata.nextLink') {
        Get-RolePermissions -Uri $response.'@odata.nextLink'
    }
}

# Fetch Permissions
$Uri = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions"
Get-RolePermissions -Uri $Uri #| Out-GridView # | Export-Csv -Path "C:\Users\UgurKoc\Downloads\permissions.csv" -NoTypeInformation

