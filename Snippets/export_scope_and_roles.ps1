# Step 1: Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementRBAC.Read.All"

# Function to Fetch Scope Tags
function Get-ScopeTags {
    param($Uri)
    $response = Invoke-MgGraphRequest -Uri $Uri -Method GET
    $scopeTags = @{}

    # Process each scope tag
    foreach ($tag in $response.value) {
        $scopeTags[$tag.id] = @{
            DisplayName = $tag.displayName
            Description = $tag.description
        }
    }

    # Recursively call for next link if available
    if ($response.'@odata.nextLink') {
        $scopeTags += Get-ScopeTags -Uri $response.'@odata.nextLink'
    }

    return $scopeTags
}

# Function to Fetch Roles and their Scope Tags
function Get-RolesWithScopeTags {
    param(
        $Uri, 
        $ScopeTags,
        [bool]$OnlyWithScopeTags = $false
    )
    $response = Invoke-MgGraphRequest -Uri $Uri -Method GET
    $rolesWithTags = @()

    # Process and return the response values for all roles
    foreach ($role in $response.value) {
        # Check if the role has scope tags
        if ($OnlyWithScopeTags -and ($role.roleScopeTagIds.Count -eq 0)) {
            continue
        }

        # Determine Role Type based on IsBuiltIn
        $roleType = if ($role.isBuiltIn) { "Built-in Role" } else { "Custom Role" }

        $roleObject = [PSCustomObject]@{
            DisplayName     = $role.displayName
            RoleType        = $roleType
            RoleDescription = $role.description
        }

        # Add scope tag details as separate properties
        for ($i = 0; $i -lt $role.roleScopeTagIds.Count; $i++) {
            $tagId = $role.roleScopeTagIds[$i]
            $tagDetails = $ScopeTags[$tagId]

            $nameSuffix = if ($role.roleScopeTagIds.Count -gt 1) { $i + 1 } else { "" }
            $roleObject | Add-Member -NotePropertyName ("ScopeTagDisplayName" + $nameSuffix) -NotePropertyValue $tagDetails.DisplayName
            $roleObject | Add-Member -NotePropertyName ("ScopeTagDescription" + $nameSuffix) -NotePropertyValue $tagDetails.Description
        }

        $rolesWithTags += $roleObject
    }

    # Recursively call for next link if available
    if ($response.'@odata.nextLink') {
        $rolesWithTags += Get-RolesWithScopeTags -Uri $response.'@odata.nextLink' -ScopeTags $ScopeTags -OnlyWithScopeTags $OnlyWithScopeTags
    }

    return $rolesWithTags
}

# Fetch Scope Tags
$scopeTagsUri = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags"
$scopeTags = Get-ScopeTags -Uri $scopeTagsUri

# Fetch Roles with Scope Tags
$rolesUri = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions"
$rolesWithScopeTags = Get-RolesWithScopeTags -Uri $rolesUri -ScopeTags $scopeTags -OnlyWithScopeTags $true

# Display the result in the console as a table
$rolesWithScopeTags | fl
