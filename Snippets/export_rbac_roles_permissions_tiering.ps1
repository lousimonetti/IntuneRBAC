# Step 1: Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementRBAC.Read.All"

# Define Tier Criteria
$Tier0Permissions = @('Microsoft.Intune_DeviceConfigurations_Assign','Microsoft.Intune_DeviceConfigurations_Update')
$Tier1Permissions = @('*create*', '*read*')
#$Tier2Permissions = @() 

# Step 2: Function to Fetch Permissions
function Get-RolePermissions {
    param($Uri)
    $response = Invoke-MgGraphRequest -Uri $Uri -Method GET

    # Process and return the response values for all roles
    foreach ($role in $response.value) {
        $allowedActions = @()
        $matchingPermissions = @()

        foreach ($perm in $role.rolePermissions) {
            foreach ($action in $perm.resourceActions) {
                $allowedActions += $action.allowedResourceActions
            }
        }

        # Determine the Tier and Store Matching Permissions
        $tier = 2 # Default to Tier 2
        $matchedTier0 = $allowedActions | Where-Object { $_ -in $Tier0Permissions }
        if ($Tier0Permissions -and $matchedTier0) {
            $tier = 0
            $matchingPermissions += $matchedTier0
        } else {
            foreach ($tier1Perm in $Tier1Permissions) {
                $matchedTier1 = $allowedActions | Where-Object { $_ -like $tier1Perm }
                if ($matchedTier1) {
                    $tier = 1
                    $matchingPermissions += $matchedTier1
                    break
                }
            }
        }

        [PSCustomObject]@{
            RoleName = $role.displayName
            #IsBuiltIn = $role.isBuiltIn
            #Description = $role.description
            #ScopeTag = $role.roleScopeTagIds
            #AllowedResourceActions = $allowedActions -join ', '
            Tier = $tier
            #TierPermissions = ($matchingPermissions -join ', ')
        }
    }

    # Recursively call for next link if available
    if ($response.'@odata.nextLink') {
        Get-RolePermissions -Uri $response.'@odata.nextLink'
    }
}

# Fetch Permissions
$Uri = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions"
Get-RolePermissions -Uri $Uri | fl # | Export-Csv -Path "C:\Users\UgurKoc\Downloads\permissions.csv" -NoTypeInformation