# Step 1: Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementRBAC.Read.All, DeviceManagementApps.Read.All, DeviceManagementConfiguration.Read.All, User.ReadBasic.All" -NoWelcome

# Get tenant information and timestamp
$tenantInfo = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization" -Method GET
$tenantName = $tenantInfo.value[0].displayName
$lastUpdated = Get-Date -Format "MMMM dd, yyyy HH:mm"
$version = "0.2.3"

# Data processing for charts
$rolesWithScopeTagsCount = 0
$rolesWithoutScopeTagsCount = 0
$customRolesCount = 0
$builtInRolesCount = 0
$unusedRolesCount = 0
$rolesWithOverlappingPermissionsCount = 0
$script:allPermissionsMatrixData = @{}
$script:allRoleNamesForMatrixData = [System.Collections.Generic.List[string]]::new()
$script:graphNodes = [System.Collections.Generic.List[object]]::new()
$script:graphLinks = [System.Collections.Generic.List[object]]::new()
$script:processedGraphNodeIds = [System.Collections.Generic.HashSet[string]]::new()

# Fetch all roles first
$rolesUri = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions"
$response = Invoke-MgGraphRequest -Uri $rolesUri -Method GET

# Process the roles for counting
foreach ($role in $response.value) {
  if ($role.roleScopeTagIds.Count -gt 0) {
    $rolesWithScopeTagsCount++
  }
  else {
    $rolesWithoutScopeTagsCount++
  }

  if ($role.isBuiltIn) {
    $builtInRolesCount++
  }
  else {
    $customRolesCount++
  }
}

function Get-RoleAssignments {
  param($roleId)
  $assignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions('$roleId')/roleAssignments"

  $response = Invoke-MgGraphRequest -Uri $assignmentsUri -Method GET

  $assignments = @()
  foreach ($assignment in $response.value) {
    $assignments += [PSCustomObject]@{
      DisplayName      = $assignment.displayName
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
      RoleAssignmentId   = $member.id
      GroupId            = $groupId
      GroupName          = $groupName
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

function Get-ScopeTags {
  param($Uri)
  $response = Invoke-MgGraphRequest -Uri $Uri -Method GET
  $scopeTags = @{}

  foreach ($tag in $response.value) {
    $scopeTags[$tag.id] = @{
      DisplayName = $tag.displayName
      Description = $tag.description
    }
  }

  if ($response.'@odata.nextLink') {
    $scopeTags += Get-ScopeTags -Uri $response.'@odata.nextLink'
  }

  return $scopeTags
}

# Function to categorize permissions
function Get-CategorizedPermissions {
  param($actions)
  $categories = @{
    'Mobile Apps'  = @()
    'Managed Apps' = @()
    'Devices'      = @()
    'Policies'     = @()
    'Filters'      = @()
    'Security'     = @()
    'Other'        = @()
    'Cloud Attach' = @()
  }

  foreach ($action in $actions) {
    switch -Wildcard ($action) {
      "Microsoft.Intune_MobileApps_*" { $categories['Mobile Apps'] += $action.Replace("Microsoft.Intune_", "") }
      "Microsoft.Intune_ManagedApps_*" { $categories['Managed Apps'] += $action.Replace("Microsoft.Intune_", "") }
      "Microsoft.Intune_Devices_*" { $categories['Devices'] += $action.Replace("Microsoft.Intune_", "") }
      "Microsoft.Intune_DeviceConfigurations_*" { $categories['Policies'] += $action.Replace("Microsoft.Intune_", "") }
      "Microsoft.Intune_Filter_*" { $categories['Filters'] += $action.Replace("Microsoft.Intune_", "") }
      "Microsoft.Intune_Security*" { $categories['Security'] += $action.Replace("Microsoft.Intune_", "") }
      "Microsoft.Intune_CloudAttach_*" { $categories['Cloud Attach'] += $action.Replace("Microsoft.Intune_", "") }
      default { $categories['Other'] += $action.Replace("Microsoft.Intune_", "") }
    }
  }
  return $categories
}

# Function to check for unused roles
function Test-UnusedRole {
  param($roleId)
  
  $assignments = Get-RoleAssignments -roleId $roleId
  return $assignments.Count -eq 0
}

# Function to find overlapping permissions between roles
function Get-OverlappingPermissions {
  param($allRoles)
  
  $overlaps = @{}
  
  # Create a lookup of role ID to permissions
  $rolePermissions = @{}
  foreach ($role in $allRoles) {
    $allowedActions = @()
    foreach ($perm in $role.rolePermissions) {
      foreach ($action in $perm.resourceActions) {
        $allowedActions += $action.allowedResourceActions
      }
    }
    $rolePermissions[$role.id] = @{
      DisplayName = $role.displayName
      Permissions = $allowedActions
    }
  }
  
  # Compare each role with every other role
  foreach ($roleId in $rolePermissions.Keys) {
    $overlaps[$roleId] = @{}
    foreach ($otherRoleId in $rolePermissions.Keys) {
      if ($roleId -ne $otherRoleId) {
        $commonPermissions = Compare-Object -ReferenceObject $rolePermissions[$roleId].Permissions -DifferenceObject $rolePermissions[$otherRoleId].Permissions -IncludeEqual |
        Where-Object { $_.SideIndicator -eq '==' } |
        Select-Object -ExpandProperty InputObject
        
        if ($commonPermissions.Count -gt 0) {
          $overlaps[$roleId][$otherRoleId] = @{
            RoleName          = $rolePermissions[$otherRoleId].DisplayName
            CommonPermissions = $commonPermissions
            OverlapPercentage = [math]::Round(($commonPermissions.Count / $rolePermissions[$roleId].Permissions.Count) * 100, 1)
          }
        }
      }
    }
  }
  
  return $overlaps
}

# Function to Fetch Roles and their Scope Tags
function Get-RolesWithScopeTags {
  param(
    $Uri,
    $ScopeTags
  )
  $response = Invoke-MgGraphRequest -Uri $Uri -Method GET
  
  # Store all roles for overlap analysis
  $allRoles = $response.value
  
  # Get overlapping permissions
  $overlappingPermissions = Get-OverlappingPermissions -allRoles $allRoles

  $htmlContent = @()

  foreach ($role in $allRoles) {
    $allowedActions = @()
    foreach ($perm in $role.rolePermissions) {
      foreach ($action in $perm.resourceActions) {
        $allowedActions += $action.allowedResourceActions
      }
    }

    # ---- START: Populate data for Permissions Matrix ----
    if (-not $script:allRoleNamesForMatrixData.Contains($role.displayName)) {
      $script:allRoleNamesForMatrixData.Add($role.displayName)
      # When a new role is added, existing permissions in the matrix need an entry for this new role, defaulting to false
      foreach ($existingPermName in $script:allPermissionsMatrixData.Keys) {
        if (-not $script:allPermissionsMatrixData[$existingPermName].ContainsKey($role.displayName)) {
          $script:allPermissionsMatrixData[$existingPermName][$role.displayName] = $false
        }
      }
    }

    foreach ($permissionString in $allowedActions) {
      $cleanPermissionName = $permissionString.Replace("Microsoft.Intune_", "")
      if (-not $script:allPermissionsMatrixData.ContainsKey($cleanPermissionName)) {
        $script:allPermissionsMatrixData[$cleanPermissionName] = @{}
        # For a new permission, initialize for all known roles with false
        foreach ($knownRoleName in $script:allRoleNamesForMatrixData) {
          if (-not $script:allPermissionsMatrixData[$cleanPermissionName].ContainsKey($knownRoleName)) {
            $script:allPermissionsMatrixData[$cleanPermissionName][$knownRoleName] = $false
          }
        }
      }
      # Ensure the current role has an entry for this permission
      if (-not $script:allPermissionsMatrixData[$cleanPermissionName].ContainsKey($role.displayName)) {
        $script:allPermissionsMatrixData[$cleanPermissionName][$role.displayName] = $false # Initialize if somehow missed
      }
      $script:allPermissionsMatrixData[$cleanPermissionName][$role.displayName] = $true
    }
    # ---- END: Populate data for Permissions Matrix ----

    # Security Analysis
    $isUnused = Test-UnusedRole -roleId $role.id
    $hasOverlappingPermissions = $overlappingPermissions[$role.id].Count -gt 0
    
    # Update counters
    if ($isUnused) { $script:unusedRolesCount++ }
    if ($hasOverlappingPermissions) { $script:rolesWithOverlappingPermissionsCount++ }

    $roleType = if ($role.isBuiltIn) { "Built-In Role" } else { "Custom Role" }
        
    # Format scope tag information
    $scopeTagInfo = ""
    if ($role.roleScopeTagIds.Count -gt 0) {
      $scopeTags = @()
      foreach ($tagId in $role.roleScopeTagIds) {
        $tagDetails = $ScopeTags[$tagId]
        $scopeTags += $tagDetails.DisplayName
      }
      $scopeTagInfo = "<div class='scope-tag'><strong>Scope Tag:</strong> $($scopeTags -join ', ')</div>"
    }
    else {
      $scopeTagInfo = "<div class='no-scope-tag'>No Scope Tag assigned</div>"
    }

    # Create security badges
    $securityBadges = "<div class='accordion-badges'>"
    if ($isUnused) {
      $securityBadges += "<span class='security-badge warning'><i class='fas fa-exclamation-triangle'></i> Unused Role</span>"
    }
    if ($hasOverlappingPermissions) {
      $securityBadges += "<span class='security-badge info'><i class='fas fa-info-circle'></i> Overlapping Permissions</span>"
    }
    $securityBadges += "</div>"

    # Start the accordion for each role
    $htmlContent += "<button class='accordion'><div class='accordion-header'><span class='accordion-title'>$($role.displayName)</span>$securityBadges</div></button>"
    $htmlContent += "<div class='panel'>"
    $htmlContent += "<div class='panel-content'>"

    # Top Panel with Basic Info and Role Assignments side by side
    $htmlContent += "<div class='panel-top'>"
        
    # Basic Info Section
    $htmlContent += "<div class='panel-top-section'>"
    $htmlContent += "<h3><i class='fas fa-info-circle'></i>Basic Information</h3>"
    $htmlContent += "<p><strong>Description:</strong> $($role.description)</p>"
    $htmlContent += "<p><strong>Type:</strong> $roleType</p>"
    $htmlContent += $scopeTagInfo
    $htmlContent += "</div>"

    # Role Assignment Section (if exists)
    $roleAssignments = Get-RoleAssignments -roleId $role.id
    if ($roleAssignments) {
      $htmlContent += "<div class='panel-top-section'>"
      $htmlContent += "<h3><i class='fas fa-users'></i>Role Assignments</h3>"
      foreach ($assignment in $roleAssignments) {
        $roleMembers = Get-RoleMembers -roleDefinitionId $assignment.RoleDefinitionId
        foreach ($member in $roleMembers) {
          $groupMembers = Get-GroupMembers -groupId $member.GroupId
          $upns = $groupMembers -join ", "

          $htmlContent += "<p><strong>Assignment:</strong> $($member.RoleAssignmentName)</p>"
          $htmlContent += "<p><strong>Group:</strong> $($member.GroupName)</p>"
          $htmlContent += "<p><strong>Members:</strong> $upns</p>"
        }
      }
      $htmlContent += "</div>"
    }
    else {
      $htmlContent += "<div class='panel-top-section warning-section'>"
      $htmlContent += "<h3><i class='fas fa-exclamation-triangle'></i>Unused Role</h3>"
      $htmlContent += "<p>This role is not assigned to any groups or users.</p>"
      $htmlContent += "<p>Consider removing this role if it's not needed or assign it to appropriate groups.</p>"
      $htmlContent += "</div>"
    }
    $htmlContent += "</div>" # Close panel-top
    
    # Security Analysis Section (Only show if overlaps exist)
    if ($hasOverlappingPermissions) {
      $htmlContent += "<div class='security-analysis'>"
      $htmlContent += "<h3><i class='fas fa-shield-alt'></i>Security Analysis</h3>"
            
      # Overlapping Permissions
      if ($hasOverlappingPermissions) {
        $htmlContent += "<div class='security-section info-section'>"
        $htmlContent += "<h4><i class='fas fa-info-circle'></i>Overlapping Permissions</h4>"
        $htmlContent += "<p>This role has significant permission overlap with the following roles:</p>"
        $htmlContent += "<ul class='overlap-list'>"
        
        # Get top 3 overlapping roles by percentage
        $topOverlaps = $overlappingPermissions[$role.id].GetEnumerator() |
        Sort-Object { $_.Value.OverlapPercentage } -Descending |
        Select-Object -First 3
        
        foreach ($overlap in $topOverlaps) {
          $htmlContent += "<li><strong>$($overlap.Value.RoleName):</strong> $($overlap.Value.OverlapPercentage)% overlap ($($overlap.Value.CommonPermissions.Count) permissions)</li>"
        }
        
        $htmlContent += "</ul>"
        $htmlContent += "</div>"
      }
      
      $htmlContent += "</div>" # Close security-analysis
    }

    # Bottom Panel (Resource Actions)
    $htmlContent += "<div class='panel-bottom'>"
    if ($allowedActions) {
      $categories = Get-CategorizedPermissions -actions $allowedActions
      $totalPermissions = ($allowedActions | Measure-Object).Count
      $categoryCount = ($categories.Keys | Where-Object { $categories[$_].Count -gt 0 } | Measure-Object).Count

      $htmlContent += "<div class='resource-actions'>"
      $htmlContent += "<div class='resource-actions-header'>"
      $htmlContent += "<div class='resource-actions-title'>"
      $htmlContent += "<h3><i class='fas fa-shield-alt'></i>Allowed Resource Actions</h3>"
      $htmlContent += "<span class='resource-actions-count'>This role has $totalPermissions permissions across $categoryCount categories</span>"
      $htmlContent += "</div>"
      $htmlContent += "<input type='text' class='permission-search' placeholder='Search permissions...' onkeyup='filterPermissions(this)'>"
      $htmlContent += "</div>"

      # Tabs
      $htmlContent += "<div class='permission-tabs'>"
      $htmlContent += "<button class='permission-tab active' onclick='showCategory(this, `"all`")'>All Permissions</button>"
      foreach ($category in $categories.Keys | Where-Object { $categories[$_].Count -gt 0 }) {
        $htmlContent += "<button class='permission-tab' onclick='showCategory(this, `"$category`")'>$category</button>"
      }
      $htmlContent += "</div>"

      # Categories
      foreach ($category in $categories.Keys) {
        if ($categories[$category].Count -gt 0) {
          $htmlContent += "<div class='permission-category' data-category='$category'>"
          $htmlContent += "<div class='category-header'>"
          $htmlContent += "<span class='category-title'>$category</span>"
          $htmlContent += "<span class='category-count'>$($categories[$category].Count)</span>"
          $htmlContent += "</div>"
          $htmlContent += "<div class='permission-list'>"
          foreach ($permission in $categories[$category]) {
            $htmlContent += "<div class='permission-item'>"
            $htmlContent += "<span class='permission-icon'></span>"
            $htmlContent += "<span class='permission-name'>$permission</span>"
            $htmlContent += "</div>"
          }
          $htmlContent += "</div>"
          $htmlContent += "</div>"
        }
      }
      $htmlContent += "</div>" # Close resource-actions
    }
    $htmlContent += "</div>" # Close panel-bottom

    $htmlContent += "</div>" # Close panel-content
    $htmlContent += "</div>" # Close panel

    # ---- START: Populate data for Interactive Role Relationship Diagram ----
    try {
      # Add Role Node
      if ($script:processedGraphNodeIds.Add($role.id)) {
        $script:graphNodes.Add(@{
            id               = $role.id
            label            = $role.displayName
            type             = "role"
            title            = "Role: $($role.displayName)<br>Built-in: $($role.isBuiltIn)<br>Permissions: $($allowedActions.Count)"
            group            = "role" # For vis.js styling
            builtin          = $role.isBuiltIn # Store for tooltip or other logic
            permissionsCount = $allowedActions.Count # Store for tooltip
          })
      }

      # Get assignments for this role
      $roleAssignmentsForGraph = Get-RoleAssignments -roleId $role.id
      if ($roleAssignmentsForGraph) {
        foreach ($assignmentItem in $roleAssignmentsForGraph) {
          # $assignmentItem.RoleDefinitionId is actually the RoleAssignmentId here based on Get-RoleAssignments structure
          $roleMembersForGraph = Get-RoleMembers -roleDefinitionId $assignmentItem.RoleDefinitionId
          if ($roleMembersForGraph) {
            foreach ($groupMemberItem in $roleMembersForGraph) {
              # Add Group Node
              if ($script:processedGraphNodeIds.Add($groupMemberItem.GroupId)) {
                $script:graphNodes.Add(@{
                    id    = $groupMemberItem.GroupId
                    label = $groupMemberItem.GroupName
                    type  = "group"
                    title = "Group: $($groupMemberItem.GroupName)"
                    group = "group"
                  })
              }
              # Add Role-to-Group Link
              $script:graphLinks.Add(@{
                  from = $role.id
                  to   = $groupMemberItem.GroupId
                  type = "role_to_group" # For styling/filtering
                })

              # Get users in this group
              $userUpnsInGroup = Get-GroupMembers -groupId $groupMemberItem.GroupId
              if ($userUpnsInGroup) {
                foreach ($userUpn in $userUpnsInGroup) {
                  # Add User Node (use UPN as ID for users for simplicity, ensure it's unique)
                  $userIdForGraph = "user_" + $userUpn # Prefix to avoid collision with other IDs
                  if ($script:processedGraphNodeIds.Add($userIdForGraph)) {
                    $script:graphNodes.Add(@{
                        id      = $userIdForGraph
                        label   = $userUpn.Split('@')[0] # Display username part
                        type    = "user"
                        title   = "User: $($userUpn)"
                        group   = "user"
                        fullUpn = $userUpn
                      })
                  }
                  # Add Group-to-User Link
                  $script:graphLinks.Add(@{
                      from = $groupMemberItem.GroupId
                      to   = $userIdForGraph
                      type = "group_to_user"
                    })
                }
              }
            }
          }
        }
      }
    }
    catch {
      Write-Warning "Error populating graph data for role $($role.displayName): $($_.Exception.Message)"
    }
    # ---- END: Populate data for Interactive Role Relationship Diagram ----
  }

  # Final pass to ensure matrix is complete and sort role names
  foreach ($permNameKey in $script:allPermissionsMatrixData.Keys) {
    foreach ($roleNameKey in $script:allRoleNamesForMatrixData) {
      if (-not $script:allPermissionsMatrixData[$permNameKey].ContainsKey($roleNameKey)) {
        $script:allPermissionsMatrixData[$permNameKey][$roleNameKey] = $false
      }
    }
  }
  $script:allRoleNamesForMatrixData.Sort() # Sort roles once after all are collected and matrix is finalized

  return $htmlContent
}

function Generate-PermissionsMatrixHtml {
  $matrixHtml = @()
  $matrixHtml += "<h2 id='permissions-matrix-section'><i class='fas fa-table'></i> Permissions Matrix</h2>"
  $matrixHtml += "<div class='permissions-matrix-container'>" # ID moved to H2 for direct navigation
  $matrixHtml += "<table class='permissions-matrix-table'>"
  $matrixHtml += "<thead><tr><th>Permission</th>"

  # Role names are already sorted in $script:allRoleNamesForMatrixData by Get-RolesWithScopeTags
  foreach ($roleName in $script:allRoleNamesForMatrixData) {
    $matrixHtml += "<th>$($roleName)</th>"
  }
  $matrixHtml += "</tr></thead>"
  $matrixHtml += "<tbody>"

  # Sort permission names for row display
  $sortedPermissionNames = $script:allPermissionsMatrixData.Keys | Sort-Object

  foreach ($permissionName in $sortedPermissionNames) {
    $matrixHtml += "<tr><td>$($permissionName)</td>" # Permission names are already cleaned
    foreach ($roleName in $script:allRoleNamesForMatrixData) {
      # Use the sorted list for column order
      $hasPermission = $script:allPermissionsMatrixData[$permissionName].ContainsKey($roleName) -and $script:allPermissionsMatrixData[$permissionName][$roleName]
      $cellContent = if ($hasPermission) { "<span class='permission-check'>✔️</span>" } else { "<span class='permission-no'></span>" }
      $matrixHtml += "<td>$cellContent</td>"
    }
    $matrixHtml += "</tr>"
  }
  $matrixHtml += "</tbody></table></div>"
  return ($matrixHtml -join "`r`n")
}

# Fetch Scope Tags
$scopeTagsUri = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags"
$scopeTags = Get-ScopeTags -Uri $scopeTagsUri

# Fetch Roles with Scope Tags
$rolesUri = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions"
$htmlRolesWithScopeTags = Get-RolesWithScopeTags -Uri $rolesUri -ScopeTags $scopeTags

# Calculate total number of roles
$totalRolesCount = $rolesWithScopeTagsCount + $rolesWithoutScopeTagsCount

# Get the number of scope tags
$scopeTagsCount = $scopeTags.Count

# Create HTML file content
$navigationButtons = @"
        <a href="#rbac-statistics-section" class="hero-button">
          <i class="fas fa-chart-bar"></i> RBAC Stats
        </a>
        <a href="#security-analysis-section" class="hero-button">
          <i class="fas fa-shield-alt"></i> Security Analysis
        </a>
        <a href="#roles-overview-section" class="hero-button">
          <i class="fas fa-user-cog"></i> Roles Overview
        </a>
        <a href="#permissions-matrix-section" class="hero-button">
          <i class="fas fa-table"></i> Permissions Matrix
        </a>
        <a href="#role-relationship-diagram-section" class="hero-button">
          <i class="fas fa-project-diagram"></i> Relationship Diagram
        </a>
"@

$htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
<title>Intune RBAC Health Check</title>
<style>
:root {
  --primary-color: #2D3047;
  --primary-light: #419D78;
  --primary-dark: #1A1B2E;
  --secondary-color: #00B2CA;
  --secondary-dark: #0899AF;
  --accent-color: #419D78;
  --accent-light: #5CBA97;
  --background-color: #ffffff;
  --surface-color: #F8FAFC;
  --text-color: #2D3047;
  --card-background: #ffffff;
  --border-color: #E2E8F0;
  --error-color: #EF476F;
  --warning-color: #FF9F1C;
  --warning-rgb: 255, 159, 28; /* RGB for rgba */
  --info-color: #2196F3;
  --info-rgb: 33, 150, 243; /* RGB for rgba */
}

body {
  background-color: var(--background-color);
  color: var(--text-color);
  font-family: 'Segoe UI', Arial, sans-serif;
  margin: 0;
  padding: 0;
  line-height: 1.6;
}

.hero {
  background: linear-gradient(135deg, 
    #2D3047 0%,    /* Deep Navy */
    #419D78 50%,   /* Emerald Green */
    #00B2CA 100%   /* Turquoise */
  );
  color: white;
  padding: 20px 40px 100px;  /* Increased bottom padding */
  position: relative;
  overflow: hidden;
}

.hero::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.05'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
  opacity: 0.07; /* Slightly reduced opacity */
}

.hero-content {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  text-align: center;
}

.hero-meta {
  display: flex;
  justify-content: center;
  gap: 24px;
  margin-bottom: 24px;
  font-size: 0.9em;
  opacity: 0.9;
}

.hero-meta-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 12px;
  background: rgba(255, 255, 255, 0.1);
  border-radius: 6px;
}

.hero-meta-item i {
  opacity: 0.8;
  font-size: 14px;
}

.hero-main {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 24px;
}

.hero-title-section {
  text-align: center;
}

.hero h1 {
  font-size: 2.5em;
  margin: 0;
  padding: 0;
  border: none;
  color: white;
  text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  line-height: 1.2;
}

.hero-subtitle {
  font-size: 1.1em;
  margin: 12px 0 0 0;
  opacity: 0.9;
  font-weight: 300;
  text-align: center;
}

.hero-buttons {
  display: flex;
  justify-content: center;
  gap: 12px;
  margin-top: 24px;  /* Increased top margin */
  margin-bottom: 20px;  /* Added bottom margin */
  flex-wrap: wrap; /* Allow buttons to wrap on smaller screens */
}

.hero-button {
  display: inline-flex;
  align-items: center;
  padding: 8px 16px;
  background-color: rgba(255, 255, 255, 0.15);
  color: white;
  text-decoration: none;
  border-radius: 6px;
  border: 1px solid rgba(255, 255, 255, 0.3);
  transition: all 0.2s ease;
  font-size: 0.9em;
  gap: 8px;
  cursor: pointer;
  position: relative;
  z-index: 2;
}

.hero-button:hover {
  background-color: rgba(255, 255, 255, 0.25);
  transform: translateY(-1px);
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
}

.hero-button i {
  font-size: 16px;
}

.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 10px;
}

h1 {
  text-align: center;
  color: var(--primary-color);
  font-size: 2.5em;
  margin-bottom: 40px;
  padding-bottom: 10px;
  border-bottom: 2px solid var(--primary-color);
}

h2 {
  color: var(--accent-color);
  font-size: 1.8em;
  margin-top: 30px;
  display: flex; /* Added for icon alignment */
  align-items: center;
  gap: 10px;
  margin-bottom: 15px; /* Added default bottom margin */
}

/* Specific spacing for headers within stats container */
.stats-container h2 {
    margin-bottom: 25px; /* Increased bottom margin */
}
#security-analysis-section { /* Target the h2 directly */
    margin-top: 45px; /* Increased top margin */
}


.stats-container {
  background-color: var(--surface-color);
  border-radius: 10px;
  padding: 30px;
  margin-top: -80px;  /* Adjusted to be smaller than hero's bottom padding */
  margin-bottom: 30px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  position: relative;
  z-index: 1;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); /* Adjusted minmax */
  gap: 25px; /* Increased gap */
  margin-top: 20px;
}

.stat-card {
  background-color: var(--card-background);
  padding: 25px 20px; /* Adjusted padding */
  border-radius: 12px; /* Softer radius */
  transition: all 0.3s ease; /* Smoother transition */
  box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05); /* Softer shadow */
  border: 1px solid var(--border-color);
  display: flex; /* Use flexbox */
  flex-direction: column;
  align-items: center; /* Center items horizontally */
  justify-content: center; /* Center items vertically */
  gap: 5px; /* Reduced gap between elements */
  position: relative; /* For potential absolute elements later */
  overflow: hidden; /* Hide overflow if needed */
  text-align: center; /* Ensure text is centered */
}

.stat-card:hover {
  transform: translateY(-6px); /* Slightly more lift */
  box-shadow: 0 6px 20px rgba(0, 0, 0, 0.08); /* Enhanced shadow on hover */
}

.stat-card-icon {
  font-size: 1.6em; /* Icon size */
  color: var(--accent-color); /* Default icon color */
  margin-bottom: 10px; /* Space below icon */
  line-height: 1; /* Ensure icon aligns well */
}

.stat-number {
  font-size: 2.6em; /* Slightly larger number */
  font-weight: 600; /* Slightly less bold */
  color: var(--primary-color);
  margin: 0; /* Remove default margin */
  line-height: 1.1;
}

.stat-label {
  color: var(--text-color);
  font-size: 1em; /* Slightly smaller label */
  margin-top: 5px; /* Space above label */
  line-height: 1.3;
}

/* Specific icon colors for warning/info cards */
.stat-card.warning .stat-card-icon {
    color: var(--warning-color);
}
.stat-card.info .stat-card-icon {
    color: var(--info-color);
}


.chart-container {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 30px;
  margin: 40px 0;
  padding: 20px;
  background-color: var(--surface-color);
  border-radius: 10px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.canvas-chart {
  background-color: var(--card-background);
  padding: 20px;
  border-radius: 8px;
  min-height: 300px;
  border: 1px solid var(--border-color);
}

.accordion {
  background-color: var(--surface-color);
  color: var(--text-color);
  cursor: pointer;
  padding: 18px;
  width: 100%;
  border: 1px solid var(--border-color);
  text-align: left;
  outline: none;
  font-size: 15px;
  transition: 0.3s;
  border-radius: 8px;
  margin-bottom: 5px;
  display: block;
}

.accordion-header {
  display: flex;
  align-items: center;
  width: 100%;
  justify-content: space-between;
}

.accordion-title {
  font-weight: bold;
}

.accordion-badges {
  display: flex;
  gap: 5px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.security-badge {
  display: inline-flex;
  align-items: center;
  margin-left: 5px;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 0.8em;
  font-weight: normal;
  white-space: nowrap;
}

.security-badge i {
  margin-right: 5px;
}

.security-badge.warning {
  background-color: var(--warning-color);
  color: white;
}

.security-badge.info {
  background-color: var(--info-color);
  color: white;
}

.accordion:after {
  content: '+';
  color: var(--primary-color);
  font-weight: bold;
  float: right;
  margin-left: 5px;
  font-size: 20px;
}

.active:after {
  content: '−';
}

.active, .accordion:hover {
  background-color: var(--card-background);
  color: var(--primary-color);
}

.panel {
  padding: 0;
  background-color: var(--card-background);
  max-height: 0;
  overflow: hidden;
  transition: max-height 0.3s ease-out;
  border-radius: 0 0 8px 8px;
  margin-bottom: 10px;
  border: 1px solid var(--border-color);
  border-top: none;
}

.panel.active {
  padding: 20px;
  max-height: none;
}

.panel-content {
    display: flex;
    flex-direction: column;
    gap: 20px;
    padding: 20px;
}

.panel-top {
    display: flex;
    gap: 20px;
}

.panel-top-section {
    flex: 1;
    background-color: var(--surface-color);
    padding: 15px;
    border-radius: 8px;
    border: 1px solid var(--border-color);
}

.panel-top-section h3 {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 0 0 10px 0;
}

.panel-bottom {
    width: 100%;
}

.scope-tag {
    color: var(--accent-color);
    margin-top: 15px;
}

.no-scope-tag {
    color: #666;
    font-style: italic;
}

.resource-actions {
    background-color: var(--surface-color);
    padding: 20px;
    border-radius: 8px;
    margin-top: 20px;
    border: 1px solid var(--border-color);
    max-height: 600px;
    overflow-y: auto;
}

.resource-actions-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
}

.resource-actions-title {
    display: flex;
    align-items: center;
    gap: 10px;
}

.resource-actions-title h3 {
    margin: 0;
    color: var(--text-color);
    display: flex;
    align-items: center;
    gap: 10px;
}

.resource-actions-title h3 i {
    margin-right: 5px;
}

.resource-actions-count {
    color: var(--text-color);
    font-size: 0.9em;
}

.permission-search {
    padding: 8px 12px;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    width: 250px;
    font-size: 14px;
}

.permission-tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 5px;
    margin: 20px 0;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 10px;
}

.permission-tab {
    padding: 8px 16px;
    border: none;
    background: none;
    cursor: pointer;
    color: var(--text-color);
    font-size: 14px;
    border-radius: 4px;
    transition: all 0.3s;
}

.permission-tab:hover {
    background-color: var(--border-color);
}

.permission-tab.active {
    background-color: var(--accent-color);
    color: white;
}

.permission-category {
    display: block;
    margin-top: 20px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border-color);
}

.permission-category:last-child {
    border-bottom: none;
}

.category-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
}

.category-title {
    font-size: 1.1em;
    color: var(--text-color);
    font-weight: 600;
}

.category-count {
    background-color: var(--surface-color);
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.9em;
    color: var(--text-color);
}

.permission-list {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 10px;
}

.permission-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px;
    background-color: var(--surface-color);
    border-radius: 4px;
    border: 1px solid var(--border-color);
}

.permission-icon {
    width: 8px;
    height: 8px;
    background-color: var(--secondary-color);
    border-radius: 50%;
}

.permission-name {
    font-size: 0.9em;
    color: var(--text-color);
}

.security-badge {
    display: inline-flex;
    align-items: center;
    margin-left: 10px;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 0.8em;
    font-weight: normal;
}

.security-badge i {
    margin-right: 5px;
}

.security-badge.warning {
    background-color: var(--warning-color);
    color: white;
}

.security-badge.info {
    background-color: var(--info-color);
    color: white;
}

.security-analysis {
    margin: 20px 0;
    padding: 20px;
    background-color: var(--surface-color);
    border-radius: 8px;
    border: 1px solid var(--border-color);
}

.security-analysis h3 {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 0;
    margin-bottom: 15px;
    color: var(--text-color);
}

.security-section {
    margin-bottom: 15px;
    padding: 15px;
    border-radius: 8px;
    border: 1px solid var(--border-color);
}

.warning-section {
    background-color: rgba(255, 159, 28, 0.1);
    border-left: 4px solid var(--warning-color);
}

.info-section {
    background-color: rgba(33, 150, 243, 0.1);
    border-left: 4px solid var(--info-color);
}

.security-section h4 {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 0;
    margin-bottom: 10px;
}

.gap-list, .overlap-list {
    margin: 10px 0;
    padding-left: 20px;
}

.gap-list li, .overlap-list li {
    margin-bottom: 5px;
}

.stat-card.warning {
    border-left: 5px solid var(--warning-color); /* Thicker border */
    background-color: rgba(var(--warning-rgb), 0.03); /* Subtle background tint */
}

.stat-card.info {
    border-left: 5px solid var(--info-color); /* Thicker border */
    background-color: rgba(var(--info-rgb), 0.03); /* Subtle background tint */
}

/* Removed .stat-card.critical as the feature was removed */

@media screen and (max-width: 768px) {
    border-left: 4px solid var(--error-color); /* Match badge color */
}

@media screen and (max-width: 768px) {
    .panel-top {
        flex-direction: column;
    }
}

.footer {
    background-color: var(--surface-color);
    padding: 20px 0;
    margin-top: 40px;
    border-top: 1px solid var(--border-color);
    text-align: center;
}

.footer-content {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 20px;
}

.footer-text {
    color: var(--text-color);
    font-size: 1em;
    margin: 0;
}

.footer-link {
    color: var(--accent-color);
    text-decoration: none;
    font-weight: 500;
    transition: color 0.3s ease;
}

.footer-link:hover {
    color: var(--accent-light);
}

/* Styles for Permissions Matrix Table */
.permissions-matrix-container {
  margin-top: 40px;
  overflow-x: auto; /* For wide tables */
  padding-bottom: 20px; /* Space for horizontal scrollbar if needed */
  background-color: var(--background-color); /* Ensure container has a background for sticky elements */
}

.permissions-matrix-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9em;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
  /* background-color: var(--card-background); No background here, let rows/cells define it */
  border: 1px solid var(--border-color);
}

.permissions-matrix-table th,
.permissions-matrix-table td {
  border: 1px solid var(--border-color);
  padding: 10px 14px; /* Increased padding */
  text-align: left;
  min-width: 120px; /* Minimum width for role columns */
  background-color: var(--card-background); /* Default cell background */
}

.permissions-matrix-table th:first-child, /* Permission column header */
.permissions-matrix-table td:first-child { /* Permission column cells */
  min-width: 280px; /* Wider for permission names */
  position: sticky;
  left: 0;
  /* background-color will be set by th or tr:nth-child rules */
  z-index: 2; /* Above normal cells, below main header */
  border-right: 2px solid var(--primary-dark); /* Emphasize sticky column */
}


.permissions-matrix-table th { /* All header cells */
  background-color: var(--surface-color);
  color: var(--primary-color);
  font-weight: bold;
  position: sticky;
  top: 0;
  z-index: 3; /* Higher z-index for header row */
  border-bottom: 2px solid var(--primary-dark); /* Emphasize header row */
}

/* Ensure top-left cell (Permission header) is also sticky and styled correctly */
.permissions-matrix-table th:first-child {
    z-index: 4 !important; /* Highest z-index for the corner */
    /* Background already set by .permissions-matrix-table th */
}


.permissions-matrix-table tbody tr:nth-child(even) td { /* Apply to td for sticky column */
  background-color: var(--surface-color);
}
/* Ensure sticky first cell in even rows matches row background */
.permissions-matrix-table tbody tr:nth-child(even) td:first-child {
  background-color: var(--surface-color);
}
/* Ensure sticky first cell in odd rows matches default cell background */
.permissions-matrix-table tbody tr:nth-child(odd) td:first-child {
  background-color: var(--card-background);
}


.permissions-matrix-table tbody tr:hover td { /* Apply to all tds in hovered row */
  background-color: #e0e7ef; /* A slightly different hover, less intense */
}
/* Ensure sticky first cell in hovered row matches hover background */
.permissions-matrix-table tbody tr:hover td:first-child {
  background-color: #e0e7ef;
}


.permission-check {
  color: var(--accent-color);
  font-weight: bold;
  text-align: center;
  display: block;
  font-size: 1.2em; /* Make checkmark slightly larger */
}
.permission-no { /* For empty cells, if specific styling is desired */
    display: block;
    text-align: center;
    color: #cccccc; /* e.g., a light grey dash or x */
    font-size: 1.2em;
}
/* End of Styles for Permissions Matrix Table */
</style>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
<div class="hero">
  <div class="hero-content">
    <div class="hero-meta">
      <div class="hero-meta-item">
        <i class="fas fa-code-branch"></i>
        <span>Version $version</span>
      </div>
      <div class="hero-meta-item">
        <i class="fas fa-building"></i>
        <span>Tenant: $tenantName</span>
      </div>
      <div class="hero-meta-item">
        <i class="fas fa-clock"></i>
        <span>Generated: $lastUpdated</span>
      </div>
    </div>
    <div class="hero-main">
      <div class="hero-title-section">
        <h1>Intune RBAC Health Check</h1>
        <p class="hero-subtitle">Comprehensive overview of your Intune Role-Based Access Control configuration</p>
      </div>
      <div class="hero-buttons">
        <a href="https://github.com/ugurkocde/IntuneRBAC" target="_blank" class="hero-button">
          <i class="fab fa-github"></i>
          View on GitHub
        </a>
        <a href="https://github.com/ugurkocde/IntuneRBAC/issues" target="_blank" class="hero-button">
          <i class="fas fa-comment"></i>
          Provide Feedback
        </a>
$navigationButtons
      </div>
    </div>
  </div>
</div>
<div class="container">
  <!-- Statistics Section -->
  <div class='stats-container' id='rbac-statistics-section'>
    <h2><i class='fas fa-chart-pie'></i>RBAC Statistics</h2>
    <div class='stats-grid'>
      <div class='stat-card'>
        <div class='stat-card-icon'><i class='fas fa-users-cog'></i></div>
        <div class='stat-number'>$totalRolesCount</div>
        <div class='stat-label'>Total Intune Roles</div>
      </div>
      <div class='stat-card'>
        <div class='stat-card-icon'><i class='fas fa-user-edit'></i></div>
        <div class='stat-number'>$customRolesCount</div>
        <div class='stat-label'>Custom Roles</div>
      </div>
      <div class='stat-card'>
        <div class='stat-card-icon'><i class='fas fa-tags'></i></div>
        <div class='stat-number'>$scopeTagsCount</div>
        <div class='stat-label'>Scope Tags</div>
      </div>
    </div>
    
    <h2 id='security-analysis-section'><i class='fas fa-shield-alt'></i>Security Analysis</h2>
    <div class='stats-grid'>
      <div class='stat-card warning'>
        <div class='stat-card-icon'><i class='fas fa-ban'></i></div>
        <div class='stat-number'>$unusedRolesCount</div>
        <div class='stat-label'>Unused Roles</div>
      </div>
      <div class='stat-card info'>
        <div class='stat-card-icon'><i class='fas fa-layer-group'></i></div>
        <div class='stat-number'>$rolesWithOverlappingPermissionsCount</div>
        <div class='stat-label'>Roles with Overlapping Permissions</div>
      </div>
    </div>
  </div>
"@

$htmlRolesOverviewHeader = @"
<div id='roles-overview-section'>
  <h2><i class='fas fa-user-cog'></i> Roles Overview</h2>
</div>
"@

$htmlFooter = @"
</div>
<footer class="footer">
    <div class="footer-content">
        <p class="footer-text">Created by <a href="https://www.linkedin.com/in/ugurkocde/" target="_blank" class="footer-link">Ugur Koc</a></p>
    </div>
</footer>
<script>
document.addEventListener('DOMContentLoaded', (event) => {
    // Accordion functionality
    var acc = document.getElementsByClassName("accordion");
    for (var i = 0; i < acc.length; i++) {
        acc[i].addEventListener("click", function() {
            this.classList.toggle("active");
            var panel = this.nextElementSibling;
            if (panel.style.maxHeight) {
                panel.style.maxHeight = null;
                panel.classList.remove("active");
            } else {
                panel.classList.add("active");
                // Show all categories by default
                panel.querySelectorAll('.permission-category').forEach(cat => {
                    cat.style.display = 'block';
                });
                // Set active tab to "All Permissions"
                panel.querySelector('.permission-tab').classList.add('active');
                // Set max height to allow scrolling
                panel.style.maxHeight = panel.scrollHeight + "px";
            }
        });
    }

    // Add smooth scrolling for the resource actions section
    document.querySelectorAll('.resource-actions').forEach(section => {
        section.style.scrollBehavior = 'smooth';
    });
});

function showCategory(button, category) {
    // Update active tab
    document.querySelectorAll('.permission-tab').forEach(tab => tab.classList.remove('active'));
    button.classList.add('active');

    // Show/hide categories
    document.querySelectorAll('.permission-category').forEach(cat => {
        if (category === 'all') {
            cat.style.display = 'block';
        } else {
            cat.style.display = cat.dataset.category === category ? 'block' : 'none';
        }
    });
}

function filterPermissions(input) {
    const filter = input.value.toLowerCase();
    document.querySelectorAll('.permission-item').forEach(item => {
        const text = item.querySelector('.permission-name').textContent.toLowerCase();
        item.style.display = text.includes(filter) ? '' : 'none';
    });
}
</script>
</body>
</html>
"@

function Generate-RoleRelationshipDiagramHtml {
  param(
    [System.Collections.Generic.List[object]]$Nodes,
    [System.Collections.Generic.List[object]]$Links
  )

  $nodesJson = $Nodes | ConvertTo-Json -Depth 5 -Compress
  $linksJson = $Links | ConvertTo-Json -Depth 5 -Compress

  # Ensure JSON is properly escaped for embedding in a JavaScript string literal
  $escapedNodesJson = $nodesJson -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"'
  $escapedLinksJson = $linksJson -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"'

  $diagramHtml = @"
<div id='role-relationship-diagram-section' class='container-section'>
  <h2><i class='fas fa-project-diagram'></i> Interactive Role Relationship Diagram</h2>
  <div class='visualization-container'>
    <div class='visualization-controls'>
      <input type="text" id="graphSearchNodes" placeholder="Search nodes..." onkeyup="searchGraphNodes()">
      <button onclick="toggleGraphNodeType('role')">Toggle Roles</button>
      <button onclick="toggleGraphNodeType('group')">Toggle Groups</button>
      <button onclick="toggleGraphNodeType('user')">Toggle Users</button>
      <button onclick="resetGraphView()">Reset View</button>
    </div>
    <div id='roleGraphVisualization'></div>
  </div>
</div>

<style>
.visualization-container {
  background-color: var(--surface-color);
  border-radius: 10px;
  padding: 20px;
  margin: 20px 0; /* Reduced top margin */
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
  border: 1px solid var(--border-color);
}
#roleGraphVisualization {
  width: 100%;
  height: 700px; /* Increased height */
  background-color: var(--card-background);
  border: 1px solid var(--border-color);
  border-radius: 8px;
}
.visualization-controls {
  margin-bottom: 15px;
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  align-items: center;
}
.visualization-controls button {
  padding: 8px 12px; /* Adjusted padding */
  background-color: var(--accent-color);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  transition: background-color 0.2s;
  font-size: 0.9em;
}
.visualization-controls button:hover {
  background-color: var(--accent-light);
}
.visualization-controls input[type="text"] {
  padding: 8px 12px;
  border: 1px solid var(--border-color);
  border-radius: 4px;
  font-size: 0.9em;
  min-width: 200px;
}
</style>

<script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css" type="text/css" />

<script type="text/javascript">
  var graphNodes = JSON.parse('$escapedNodesJson');
  var graphEdges = JSON.parse('$escapedLinksJson');
  var network = null;
  var allNodesDataset = new vis.DataSet(graphNodes);
  var allEdgesDataset = new vis.DataSet(graphEdges);

  function drawRoleGraph() {
    var container = document.getElementById('roleGraphVisualization');
    var data = {
      nodes: allNodesDataset,
      edges: allEdgesDataset
    };
    var options = {
      nodes: {
        shape: 'dot',
        size: 18, // Slightly larger default size
        font: { size: 12, face: 'Segoe UI', color: '#333333' },
        borderWidth: 2,
        shadow: { enabled: true, size: 5, x: 2, y: 2 }
      },
      edges: {
        width: 2,
        shadow: false,
        smooth: { type: 'continuous', roundness: 0.2 },
        arrows: { to: { enabled: true, scaleFactor: 0.7 } }
      },
      physics: {
        enabled: true,
        solver: 'barnesHut',
        barnesHut: {
          gravitationalConstant: -15000, // Adjusted for better spread
          centralGravity: 0.1, // Pulls nodes slightly to center
          springLength: 150,    // Default spring length
          springConstant: 0.05,
          damping: 0.09
        },
        stabilization: { iterations: 150 } // Fewer iterations for faster load
      },
      layout: {
        hierarchical: false // Using physics-based layout
      },
      groups: {
        role:  { color: { background:'#28a745', border:'#208A38' }, shape: 'icon', icon: { face: 'FontAwesome', code: '\uf508', size: 30, color: 'white'}}, // Shield icon
        group: { color: { background:'#007bff', border:'#0062CC' }, shape: 'icon', icon: { face: 'FontAwesome', code: '\uf0c0', size: 30, color: 'white'}}, // Users icon
        user:  { color: { background:'#6c757d', border:'#545B62' }, shape: 'icon', icon: { face: 'FontAwesome', code: '\uf007', size: 25, color: 'white'}}  // User icon
      },
      interaction: {
        hover: true,
        tooltipDelay: 200,
        navigationButtons: true, // Adds zoom buttons
        keyboard: true // Allows keyboard navigation
      }
    };
    network = new vis.Network(container, data, options);

    network.on("doubleClick", function (params) {
      if (params.nodes.length > 0) {
        var nodeId = params.nodes[0];
        network.focus(nodeId, { scale: 1.5, animation: true });
      }
    });
  }

  document.addEventListener('DOMContentLoaded', function() {
    if (graphNodes.length > 0) {
      drawRoleGraph();
    } else {
      document.getElementById('roleGraphVisualization').innerHTML = '<p style="text-align:center;padding-top:20px;">No data available to display the relationship diagram.</p>';
    }
  });

  var originalNodesState = {}; // To store original color/size for reset
  allNodesDataset.getIds().forEach(function(nodeId){
    var node = allNodesDataset.get(nodeId);
    originalNodesState[nodeId] = { color: node.color, size: node.size };
  });


  function searchGraphNodes() {
    var input = document.getElementById('graphSearchNodes');
    var filter = input.value.toLowerCase();
    var nodesToUpdate = [];

    allNodesDataset.forEach(function(node) {
      var labelMatch = node.label.toLowerCase().includes(filter);
      var titleMatch = node.title ? node.title.toLowerCase().includes(filter) : false;
      var isVisible = (filter === '') ? true : (labelMatch || titleMatch);
      
      var updateObj = { id: node.id };
      if (filter === '') { // Reset to original
        updateObj.color = originalNodesState[node.id] ? originalNodesState[node.id].color : node.color; // Fallback to current if somehow not in original
        updateObj.size = originalNodesState[node.id] ? originalNodesState[node.id].size : node.size;
      } else {
        if (labelMatch || titleMatch) {
          updateObj.color = { background: '#FFD700', border: '#FFA500' }; // Highlight color
          updateObj.size = 25; // Emphasize size
        } else { // Dim non-matching nodes
          updateObj.color = { background: '#e0e0e0', border: '#cccccc' };
          updateObj.size = 10;
        }
      }
      nodesToUpdate.push(updateObj);
    });
    allNodesDataset.update(nodesToUpdate);
  }
  
  var hiddenNodeTypes = new Set();
  function toggleGraphNodeType(type) {
    if (hiddenNodeTypes.has(type)) {
        hiddenNodeTypes.delete(type);
    } else {
        hiddenNodeTypes.add(type);
    }
    var view = new vis.DataView(allNodesDataset, {
        filter: function (item) {
            return !hiddenNodeTypes.has(item.group);
        }
    });
    network.setData({nodes: view, edges: allEdgesDataset});
  }

  function resetGraphView() {
    if (network) {
        hiddenNodeTypes.clear();
        var view = new vis.DataView(allNodesDataset, {
            filter: function (item) { return true; } // Show all
        });
        network.setData({nodes: view, edges: allEdgesDataset});
        network.fit({animation: true}); // Fit all nodes back into view
        document.getElementById('graphSearchNodes').value = ''; // Clear search
        searchGraphNodes(); // Apply empty search to reset highlights
    }
  }

</script>
"@
  return $diagramHtml
}

# Combine HTML content and save to file
$permissionsMatrixHtml = Generate-PermissionsMatrixHtml
$roleRelationshipDiagramHtml = Generate-RoleRelationshipDiagramHtml -Nodes $script:graphNodes -Links $script:graphLinks
$htmlComplete = $htmlHeader + $htmlRolesOverviewHeader + ($htmlRolesWithScopeTags -join " ") + $permissionsMatrixHtml + $roleRelationshipDiagramHtml + $htmlFooter
$htmlComplete | Out-File "rbachealthcheck.html"