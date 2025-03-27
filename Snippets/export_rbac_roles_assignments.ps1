# Step 1: Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementRBAC.Read.All, User.ReadBasic.All"

# Step 2: Function to Fetch Permissions
function Get-Roles {
    param($Uri)
    $response = Invoke-MgGraphRequest -Uri $Uri -Method GET

    $roles = @()
    foreach ($role in $response.value) {
        $roles += [PSCustomObject]@{
            DisplayName = $role.displayName
            IsBuiltIn = $role.isBuiltIn
            Description = $role.description
            ScopeTag = $role.roleScopeTagIds
            id = $role.id
        }
    }

    if ($response.'@odata.nextLink') {
        $roles += Get-Roles -Uri $response.'@odata.nextLink'
    }

    return $roles
}

function Get-RoleAssignments {
    param($roleId)
    $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions('$roleId')/roleAssignments"

    $response = Invoke-MgGraphRequest -Uri $assignmentsUri -Method GET

    $assignments = @()
    foreach ($assignment in $response.value) {
        $assignments += [PSCustomObject]@{
            DisplayName = $assignment.displayName
            RoleDefinitionId = $assignment.id
        }
    }

    if ($response.'@odata.nextLink') {
        $assignments += Get-RoleAssignments -roleId $roleId
    }

    return $assignments
}

function Get-RoleMembers {
    param($roleDefinitionId)
    $membersUri = "https://graph.microsoft.com/beta/deviceManagement/roleAssignments('$roleDefinitionId')`?$expand=microsoft.graph.deviceAndAppManagementRoleAssignment/roleScopeTags"

    $response = Invoke-MgGraphRequest -Uri $membersUri -Method GET

    $members = @()
    foreach ($member in $response) {
        $groupId = $member.members -join ", " # Assuming there's only one group per member

        # Fetch the group name
        $groupUri = "https://graph.microsoft.com/beta/groups/$groupId"
        $groupResponse = Invoke-MgGraphRequest -Uri $groupUri -Method GET
        $groupName = $groupResponse.displayName

        $members += [PSCustomObject]@{
            RoleAssignmentName = $member.displayName
            RoleAssignmentId = $member.id
            GroupId = $groupId
            GroupName = $groupName
        }
    }

    return $members
}

function Get-GroupMembers {
    param($groupId)

    $groupMembersUri = "https://graph.microsoft.com/beta/groups/$groupId/members"
    $response = Invoke-MgGraphRequest -Uri $groupMembersUri -Method GET

    $userIds = @()
    foreach ($member in $response.value) {
        if ($member.id) {
            $userIds += $member.id
        }
    }

    # Check for pagination
    if ($response.'@odata.nextLink') {
        $userIds += Get-GroupMembers -groupId $groupId
    }

    $upns = @()
    foreach ($userId in $userIds) {
        $userUri = "https://graph.microsoft.com/beta/users/$userId"
        $userResponse = Invoke-MgGraphRequest -Uri $userUri -Method GET
        if ($userResponse.userPrincipalName) {
            $upns += $userResponse.userPrincipalName
        }
    }

    return $upns
}

# Fetch Permissions and Process Roles
$Uri = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions"
$roles = Get-Roles -Uri $Uri

foreach ($role in $roles) {
    $roleAssignments = Get-RoleAssignments -roleId $role.Id
    foreach ($assignment in $roleAssignments) {
        $roleMembers = Get-RoleMembers -roleDefinitionId $assignment.RoleDefinitionId
        foreach ($member in $roleMembers) {
            $groupMembers = Get-GroupMembers -groupId $member.GroupId
            $upns = $groupMembers -join ", "
            
            [PSCustomObject]@{
                IntuneRole = $role.DisplayName
                RoleAssignmentName = $member.RoleAssignmentName
                #RoleAssignmentId = $member.RoleAssignmentId
                EntraIDGroupName = $member.GroupName
                UPNs = $upns
            } | Format-List
        }
    }
}