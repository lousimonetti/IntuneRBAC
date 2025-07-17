<#PSScriptInfo
.VERSION 0.5.0
.GUID 552abbe1-5543-41a3-bd39-eab7613593f2
.AUTHOR ugurk
.COMPANYNAME
.COPYRIGHT Copyright (c) 2025 Ugur Koc | Microsoft MVP
.TAGS Intune RBAC RoleBasedAccessControl ScopeTags Permissions
.LICENSEURI https://github.com/ugurkocde/IntuneRBAC/blob/main/LICENSE
.PROJECTURI https://github.com/ugurkocde/IntuneRBAC
.ICONURI
.EXTERNALMODULEDEPENDENCIES Microsoft.Graph.Authentication
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
Version 0.5.0: Security Review Feature Release:
- Added comprehensive Security Review section with risk assessment
- Implemented multi-dimensional risk scoring for RBAC roles
- Added security recommendations engine with actionable insights
- Created compliance checks for Zero Trust and least privilege
- Added interactive security dashboard with health scores
- Implemented remediation tracking and priority guidance
- Added detailed security export for audit reports
Version 0.4.0: Major update with performance improvements and new features:
- Added Dark Mode toggle with persistent preference storage
- Added Export to CSV functionality for roles, permissions matrix, and security analysis
- Added Global Search feature with highlighting and auto-expand for matching results
- Implemented parallel processing for faster group member lookups
- Added progress tracking with ETA calculations
- Optimized HTML generation using StringBuilder for better performance
- Added batch API request capability for improved efficiency
Version 0.3.3: Added missing Group.Read.All permission to fix 404 errors when accessing group information.
Version 0.3.2: Fixed infinite loop issue when groups are deleted or inaccessible. Added proper error handling for 404 errors.
Version 0.3.1: Fixed a issue with the version number in the HTML report.
Version 0.3.0: Added welcome banner, progress messages, and option to open HTML report after generation.
Version 0.2.3: Current version with RBAC health check functionality.
Version 0.2.2: Added interactive Role Relationship Diagram.
Version 0.2.1: Added comprehensive Permissions Matrix.
Version 0.2.0: Added security analysis for unused roles and overlapping permissions.
Version 0.1.0: Initial release with basic RBAC reporting capabilities.
.PRIVATEDATA
#>

<#
.DESCRIPTION
This script provides a comprehensive analysis of Microsoft Intune's Role-Based Access Control (RBAC) configuration. It generates an interactive HTML report that includes role details, assignments, scope tags, permissions, and security analysis to help administrators audit and manage their Intune RBAC setup.
#>

#Requires -Version 7.0

$version = "0.5.0"

# Display welcome banner
Write-Host "
___       _                    ____  ____    _    ____
|_ _|_ __ | |_ _   _ _ __   ___|  _ \| __ )  / \  / ___|
 | || '_ \| __| | | | '_ \ / _ \ |_) |  _ \ / _ \| |
 | || | | | |_| |_| | | | |  __/  _ <| |_) / ___ \ |___
|___|_| |_|\__|\__,_|_| |_|\___|_| \_\____/_/   \_\____|
" -ForegroundColor Cyan

Write-Host "IntuneRBAC - Comprehensive RBAC Analysis for Microsoft Intune" -ForegroundColor Green
Write-Host "Made by Ugur Koc with" -NoNewline; Write-Host " ❤️  and ☕" -NoNewline
Write-Host " | Version" -NoNewline; Write-Host " $version" -ForegroundColor Yellow -NoNewline
Write-Host " | Last updated: " -NoNewline; Write-Host "$(Get-Date -Format "yyyy-MM-dd")" -ForegroundColor Magenta
Write-Host ""
Write-Host "GitHub: https://github.com/ugurkocde/IntuneRBAC" -ForegroundColor Cyan
Write-Host "You can sponsor the development of this project at https://github.com/sponsors/ugurkocde" -ForegroundColor Red
Write-Host ""

# Step 1: Connect to Microsoft Graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
Connect-MgGraph -Scopes "DeviceManagementRBAC.Read.All, DeviceManagementApps.Read.All, DeviceManagementConfiguration.Read.All, User.ReadBasic.All, Group.Read.All" -NoWelcome
Write-Host "Connected to Microsoft Graph successfully!" -ForegroundColor Green

# Get tenant information and timestamp
$tenantInfo = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization" -Method GET
$tenantName = $tenantInfo.value[0].displayName
$lastUpdated = Get-Date -Format "MMMM dd, yyyy HH:mm"

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

# Security Review variables
$script:securityReviewData = @{
  RoleRiskScores = @{}
  CriticalPermissions = @{}
  SecurityFindings = [System.Collections.Generic.List[object]]::new()
  ComplianceChecks = @{}
  Recommendations = [System.Collections.Generic.List[object]]::new()
  OverallHealthScore = 0
}

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

  try {
    $response = Invoke-MgGraphRequest -Uri $membersUri -Method GET
  }
  catch {
    Write-Warning "Could not fetch role assignment: $($_.Exception.Message)"
    return @()
  }

  $members = @()
  foreach ($member in $response) {
    $groupId = $member.members -join ", " # Assuming there's only one group per member

    # Skip if no group ID
    if ([string]::IsNullOrEmpty($groupId)) {
      continue
    }

    # Fetch the group name
    $groupUri = "https://graph.microsoft.com/beta/groups/$groupId"
    try {
      $groupResponse = Invoke-MgGraphRequest -Uri $groupUri -Method GET
      $groupName = $groupResponse.displayName
    }
    catch {
      Write-Warning "Group $groupId not found or inaccessible. Skipping."
      continue
    }

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

  # Skip if no group ID provided
  if ([string]::IsNullOrEmpty($groupId)) {
    return @()
  }

  $groupMembersUri = "https://graph.microsoft.com/beta/groups/$groupId/members"
  try {
    $response = Invoke-MgGraphRequest -Uri $groupMembersUri -Method GET
  }
  catch {
    Write-Warning "Could not fetch members for group ${groupId}: $($_.Exception.Message)"
    return @()
  }

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

  # Use parallel processing for user lookups if there are many users
  if ($userIds.Count -gt 10) {
    $upns = $userIds | ForEach-Object -Parallel {
      $userId = $_
      $userUri = "https://graph.microsoft.com/beta/users/$userId"
      try {
        $userResponse = Invoke-MgGraphRequest -Uri $userUri -Method GET
        if ($userResponse.userPrincipalName) {
          $userResponse.userPrincipalName
        }
      }
      catch {
        Write-Warning "Could not fetch user details for ${userId}: $($_.Exception.Message)"
      }
    } -ThrottleLimit 5
  }
  else {
    # Sequential processing for small groups
    $upns = @()
    foreach ($userId in $userIds) {
      $userUri = "https://graph.microsoft.com/beta/users/$userId"
      try {
        $userResponse = Invoke-MgGraphRequest -Uri $userUri -Method GET
        if ($userResponse.userPrincipalName) {
          $upns += $userResponse.userPrincipalName
        }
      }
      catch {
        Write-Warning "Could not fetch user details for ${userId}: $($_.Exception.Message)"
      }
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

# Security Review Functions
function Get-CriticalPermissions {
  # Define critical permissions with risk scores
  return @{
    # Device Management - Critical
    "Devices_Delete" = 40
    "Devices_Wipe" = 40
    "Devices_ResetPasscode" = 35
    "Devices_DisableLostMode" = 30
    "Devices_Retire" = 35
    "Devices_RemoteLock" = 30
    
    # App Management - High Risk
    "MobileApps_Delete" = 30
    "MobileApps_Create" = 25
    "MobileApps_Update" = 25
    "MobileApps_Assign" = 30
    
    # Policy Configuration - High Risk
    "DeviceConfigurations_Delete" = 30
    "DeviceConfigurations_Create" = 25
    "DeviceConfigurations_Update" = 25
    "DeviceConfigurations_Assign" = 30
    
    # Security Policies - Critical
    "SecurityBaselines_Update" = 35
    "SecurityBaselines_Assign" = 35
    "CompliancePolicies_Delete" = 30
    "ConditionalAccess_Update" = 40
    
    # User/Group Management - High Risk
    "EnrollmentProgramTokens_Delete" = 35
    "DepOnboardingSettings_Update" = 30
    "ManagedAppPolicies_Delete" = 25
    
    # Read Operations - Lower Risk
    "Devices_Read" = 10
    "MobileApps_Read" = 10
    "DeviceConfigurations_Read" = 10
    "Reports_Read" = 5
  }
}

function Get-PermissionRiskScore {
  param($permission)
  
  $criticalPermissions = Get-CriticalPermissions
  $cleanPermission = $permission.Replace("Microsoft.Intune_", "")
  
  # Check if it's a known critical permission
  if ($criticalPermissions.ContainsKey($cleanPermission)) {
    return $criticalPermissions[$cleanPermission]
  }
  
  # Pattern-based risk assessment
  if ($cleanPermission -match "_Delete$|_Wipe$|_Reset") { return 30 }
  if ($cleanPermission -match "_Create$|_Update$|_Assign$") { return 20 }
  if ($cleanPermission -match "_Read$|_View$") { return 10 }
  if ($cleanPermission -match "Security|Compliance|Conditional") { return 25 }
  
  # Default risk score
  return 15
}

function Calculate-RoleRiskScore {
  param(
    $role,
    $permissions,
    $assignments,
    $userCount
  )
  
  $riskScore = 0
  $riskFactors = @{}
  
  # Factor 1: Permission Criticality (0-40 points)
  $permissionScore = 0
  $criticalPermCount = 0
  foreach ($permission in $permissions) {
    $permRisk = Get-PermissionRiskScore -permission $permission
    $permissionScore += $permRisk
    if ($permRisk -ge 30) { $criticalPermCount++ }
  }
  # Normalize to 0-40 scale
  $permissionScore = [Math]::Min(40, ($permissionScore / [Math]::Max(1, $permissions.Count)) * 2)
  $riskFactors['PermissionCriticality'] = [Math]::Round($permissionScore, 1)
  
  # Factor 2: Scope (0-20 points)
  $scopeScore = 0
  if ($role.roleScopeTagIds.Count -eq 0) {
    $scopeScore = 20  # Organization-wide scope
  } elseif ($role.roleScopeTagIds.Count -gt 2) {
    $scopeScore = 15  # Multiple scopes
  } else {
    $scopeScore = 10  # Limited scope
  }
  $riskFactors['ScopeExposure'] = $scopeScore
  
  # Factor 3: User Exposure (0-20 points)
  $userScore = 0
  if ($userCount -gt 50) { $userScore = 20 }
  elseif ($userCount -gt 20) { $userScore = 15 }
  elseif ($userCount -gt 5) { $userScore = 10 }
  elseif ($userCount -gt 0) { $userScore = 5 }
  $riskFactors['UserExposure'] = $userScore
  
  # Factor 4: Configuration Risk (0-20 points)
  $configScore = 0
  if (-not $role.isBuiltIn -and $permissions.Count -gt 20) { $configScore += 10 }
  if ($criticalPermCount -gt 5) { $configScore += 10 }
  $riskFactors['ConfigurationRisk'] = $configScore
  
  # Calculate total risk score
  $riskScore = $riskFactors['PermissionCriticality'] + $riskFactors['ScopeExposure'] + 
               $riskFactors['UserExposure'] + $riskFactors['ConfigurationRisk']
  
  return @{
    TotalScore = [Math]::Round($riskScore, 1)
    Factors = $riskFactors
    Level = Get-RiskLevel -score $riskScore
    CriticalPermissionCount = $criticalPermCount
  }
}

function Get-RiskLevel {
  param($score)
  
  if ($score -ge 80) { return "Critical" }
  if ($score -ge 60) { return "High" }
  if ($score -ge 40) { return "Medium" }
  return "Low"
}

function Get-SecurityRecommendations {
  param($roleData)
  
  $recommendations = [System.Collections.Generic.List[object]]::new()
  
  foreach ($role in $roleData) {
    if ($role.RiskScore.Level -eq "Critical" -or $role.RiskScore.Level -eq "High") {
      # High risk recommendations
      if ($role.RiskScore.Factors.PermissionCriticality -gt 30) {
        $recommendations.Add(@{
          RoleId = $role.Id
          RoleName = $role.DisplayName
          Priority = "High"
          Category = "Excessive Permissions"
          Recommendation = "Review and reduce critical permissions. Consider splitting into multiple roles."
          Impact = "Reduces potential damage from compromised accounts"
        })
      }
      
      if ($role.RiskScore.Factors.ScopeExposure -eq 20) {
        $recommendations.Add(@{
          RoleId = $role.Id
          RoleName = $role.DisplayName
          Priority = "High"
          Category = "Scope Management"
          Recommendation = "Implement scope tags to limit role access to specific device groups"
          Impact = "Limits blast radius of security incidents"
        })
      }
      
      if ($role.UserCount -gt 50) {
        $recommendations.Add(@{
          RoleId = $role.Id
          RoleName = $role.DisplayName
          Priority = "Medium"
          Category = "User Management"
          Recommendation = "Large number of users ($($role.UserCount)). Consider creating sub-roles with limited permissions."
          Impact = "Follows principle of least privilege"
        })
      }
    }
    
    # Unused role recommendations
    if ($role.IsUnused) {
      $recommendations.Add(@{
        RoleId = $role.Id
        RoleName = $role.DisplayName
        Priority = "Low"
        Category = "Role Hygiene"
        Recommendation = "Role is unused. Consider removing if no longer needed."
        Impact = "Reduces attack surface"
      })
    }
  }
  
  return $recommendations
}


function Calculate-OverallHealthScore {
  param($roleData)
  
  $score = 100
  $deductions = @{}
  
  # Deduct for high-risk roles
  $criticalRoles = ($roleData | Where-Object { $_.RiskScore.Level -eq "Critical" }).Count
  $highRoles = ($roleData | Where-Object { $_.RiskScore.Level -eq "High" }).Count
  
  $deductions['CriticalRoles'] = $criticalRoles * 15
  $deductions['HighRiskRoles'] = $highRoles * 8
  
  # Deduct for medium risk roles
  $mediumRoles = ($roleData | Where-Object { $_.RiskScore.Level -eq "Medium" }).Count
  $deductions['MediumRiskRoles'] = $mediumRoles * 3
  
  # Deduct for unused roles
  $unusedCount = ($roleData | Where-Object { $_.IsUnused }).Count
  $deductions['UnusedRoles'] = [Math]::Min(15, $unusedCount * 3)
  
  # Deduct for roles with excessive permissions
  $excessivePermRoles = ($roleData | Where-Object { $_.PermissionCount -gt 50 }).Count
  $deductions['ExcessivePermissions'] = $excessivePermRoles * 5
  
  # Calculate final score
  $totalDeductions = ($deductions.Values | Measure-Object -Sum).Sum
  $finalScore = [Math]::Max(0, $score - $totalDeductions)
  
  return @{
    Score = [Math]::Round($finalScore, 1)
    Deductions = $deductions
    Grade = Get-HealthGrade -score $finalScore
  }
}

function Get-HealthGrade {
  param($score)
  
  if ($score -ge 90) { return "A" }
  if ($score -ge 80) { return "B" }
  if ($score -ge 70) { return "C" }
  if ($score -ge 60) { return "D" }
  return "F"
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

  # Use StringBuilder for better performance
  $htmlBuilder = [System.Text.StringBuilder]::new()

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
    
    # Security Review: Calculate risk score and collect data
    $roleAssignments = Get-RoleAssignments -roleId $role.id
    $totalUserCount = 0
    foreach ($assignment in $roleAssignments) {
      $roleMembers = Get-RoleMembers -roleDefinitionId $assignment.RoleDefinitionId
      foreach ($member in $roleMembers) {
        $groupMembers = Get-GroupMembers -groupId $member.GroupId
        $totalUserCount += $groupMembers.Count
      }
    }
    
    # Calculate risk score
    $riskScore = Calculate-RoleRiskScore -role $role -permissions $allowedActions -assignments $roleAssignments -userCount $totalUserCount
    
    # Store security review data
    $script:securityReviewData.RoleRiskScores[$role.id] = @{
      RoleId = $role.id
      DisplayName = $role.displayName
      RiskScore = $riskScore
      UserCount = $totalUserCount
      IsUnused = $isUnused
      HasOverlappingPermissions = $hasOverlappingPermissions
      PermissionCount = $allowedActions.Count
    }

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
    # Add risk score badge
    $riskClass = switch ($riskScore.Level) {
      "Critical" { "critical" }
      "High" { "high" }
      "Medium" { "medium" }
      default { "low" }
    }
    $securityBadges += "<span class='security-badge risk-$riskClass'><i class='fas fa-shield-alt'></i> Risk: $($riskScore.Level) ($($riskScore.TotalScore))</span>"
    $securityBadges += "</div>"

    # Start the accordion for each role
    [void]$htmlBuilder.Append("<button class='accordion'><div class='accordion-header'><span class='accordion-title'>$($role.displayName)</span>$securityBadges</div></button>")
    [void]$htmlBuilder.Append("<div class='panel'>")
    [void]$htmlBuilder.Append("<div class='panel-content'>")

    # Top Panel with Basic Info and Role Assignments side by side
    [void]$htmlBuilder.Append("<div class='panel-top'>")
        
    # Basic Info Section
    [void]$htmlBuilder.Append("<div class='panel-top-section'>")
    [void]$htmlBuilder.Append("<h3><i class='fas fa-info-circle'></i>Basic Information</h3>")
    [void]$htmlBuilder.Append("<p><strong>Description:</strong> $($role.description)</p>")
    [void]$htmlBuilder.Append("<p><strong>Type:</strong> $roleType</p>")
    [void]$htmlBuilder.Append($scopeTagInfo)
    [void]$htmlBuilder.Append("</div>")

    # Role Assignment Section (if exists)
    $roleAssignments = Get-RoleAssignments -roleId $role.id
    if ($roleAssignments) {
      [void]$htmlBuilder.Append("<div class='panel-top-section'>")
      [void]$htmlBuilder.Append("<h3><i class='fas fa-users'></i>Role Assignments</h3>")
      foreach ($assignment in $roleAssignments) {
        $roleMembers = Get-RoleMembers -roleDefinitionId $assignment.RoleDefinitionId
        foreach ($member in $roleMembers) {
          $groupMembers = Get-GroupMembers -groupId $member.GroupId
          $upns = $groupMembers -join ", "

          [void]$htmlBuilder.Append("<p><strong>Assignment:</strong> $($member.RoleAssignmentName)</p>")
          [void]$htmlBuilder.Append("<p><strong>Group:</strong> $($member.GroupName)</p>")
          if ($upns) {
            [void]$htmlBuilder.Append("<p><strong>Members:</strong> $upns</p>")
          }
          else {
            [void]$htmlBuilder.Append("<p><strong>Members:</strong> <em>No accessible members</em></p>")
          }
        }
      }
      [void]$htmlBuilder.Append("</div>")
    }
    else {
      [void]$htmlBuilder.Append("<div class='panel-top-section warning-section'>")
      [void]$htmlBuilder.Append("<h3><i class='fas fa-exclamation-triangle'></i>Unused Role</h3>")
      [void]$htmlBuilder.Append("<p>This role is not assigned to any groups or users.</p>")
      [void]$htmlBuilder.Append("<p>Consider removing this role if it's not needed or assign it to appropriate groups.</p>")
      [void]$htmlBuilder.Append("</div>")
    }
    [void]$htmlBuilder.Append("</div>") # Close panel-top
    
    # Security Analysis Section (Only show if overlaps exist)
    if ($hasOverlappingPermissions) {
      [void]$htmlBuilder.Append("<div class='security-analysis'>")
      [void]$htmlBuilder.Append("<h3><i class='fas fa-shield-alt'></i>Security Analysis</h3>")
            
      # Overlapping Permissions
      if ($hasOverlappingPermissions) {
        [void]$htmlBuilder.Append("<div class='security-section info-section'>")
        [void]$htmlBuilder.Append("<h4><i class='fas fa-info-circle'></i>Overlapping Permissions</h4>")
        [void]$htmlBuilder.Append("<p>This role has significant permission overlap with the following roles:</p>")
        [void]$htmlBuilder.Append("<ul class='overlap-list'>")
        
        # Get top 3 overlapping roles by percentage
        $topOverlaps = $overlappingPermissions[$role.id].GetEnumerator() |
        Sort-Object { $_.Value.OverlapPercentage } -Descending |
        Select-Object -First 3
        
        foreach ($overlap in $topOverlaps) {
          [void]$htmlBuilder.Append("<li><strong>$($overlap.Value.RoleName):</strong> $($overlap.Value.OverlapPercentage)% overlap ($($overlap.Value.CommonPermissions.Count) permissions)</li>")
        }
        
        [void]$htmlBuilder.Append("</ul>")
        [void]$htmlBuilder.Append("</div>")
      }
      
      [void]$htmlBuilder.Append("</div>") # Close security-analysis
    }

    # Bottom Panel (Resource Actions)
    [void]$htmlBuilder.Append("<div class='panel-bottom'>")
    if ($allowedActions) {
      $categories = Get-CategorizedPermissions -actions $allowedActions
      $totalPermissions = ($allowedActions | Measure-Object).Count
      $categoryCount = ($categories.Keys | Where-Object { $categories[$_].Count -gt 0 } | Measure-Object).Count

      [void]$htmlBuilder.Append("<div class='resource-actions'>")
      [void]$htmlBuilder.Append("<div class='resource-actions-header'>")
      [void]$htmlBuilder.Append("<div class='resource-actions-title'>")
      [void]$htmlBuilder.Append("<h3><i class='fas fa-shield-alt'></i>Allowed Resource Actions</h3>")
      [void]$htmlBuilder.Append("<span class='resource-actions-count'>This role has $totalPermissions permissions across $categoryCount categories</span>")
      [void]$htmlBuilder.Append("</div>")
      [void]$htmlBuilder.Append("<input type='text' class='permission-search' placeholder='Search permissions...' onkeyup='filterPermissions(this)'>")
      [void]$htmlBuilder.Append("</div>")

      # Tabs
      [void]$htmlBuilder.Append("<div class='permission-tabs'>")
      [void]$htmlBuilder.Append("<button class='permission-tab active' onclick='showCategory(this, `"all`")'>All Permissions</button>")
      foreach ($category in $categories.Keys | Where-Object { $categories[$_].Count -gt 0 }) {
        [void]$htmlBuilder.Append("<button class='permission-tab' onclick='showCategory(this, `"$category`")'>$category</button>")
      }
      [void]$htmlBuilder.Append("</div>")

      # Categories
      foreach ($category in $categories.Keys) {
        if ($categories[$category].Count -gt 0) {
          [void]$htmlBuilder.Append("<div class='permission-category' data-category='$category'>")
          [void]$htmlBuilder.Append("<div class='category-header'>")
          [void]$htmlBuilder.Append("<span class='category-title'>$category</span>")
          [void]$htmlBuilder.Append("<span class='category-count'>$($categories[$category].Count)</span>")
          [void]$htmlBuilder.Append("</div>")
          [void]$htmlBuilder.Append("<div class='permission-list'>")
          foreach ($permission in $categories[$category]) {
            [void]$htmlBuilder.Append("<div class='permission-item'>")
            [void]$htmlBuilder.Append("<span class='permission-icon'></span>")
            [void]$htmlBuilder.Append("<span class='permission-name'>$permission</span>")
            [void]$htmlBuilder.Append("</div>")
          }
          [void]$htmlBuilder.Append("</div>")
          [void]$htmlBuilder.Append("</div>")
        }
      }
      [void]$htmlBuilder.Append("</div>") # Close resource-actions
    }
    [void]$htmlBuilder.Append("</div>") # Close panel-bottom

    [void]$htmlBuilder.Append("</div>") # Close panel-content
    [void]$htmlBuilder.Append("</div>") # Close panel

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

  return $htmlBuilder.ToString()
}

function Generate-PermissionsMatrixHtml {
  Write-Host "Building permissions matrix table..." -ForegroundColor Yellow
  
  # Use StringBuilder for better performance
  $matrixBuilder = [System.Text.StringBuilder]::new()
  
  [void]$matrixBuilder.Append("<div style='display: flex; justify-content: space-between; align-items: center; margin-top: 40px; margin-bottom: 20px;'>")
  [void]$matrixBuilder.Append("<h2 id='permissions-matrix-section' style='margin: 0;'><i class='fas fa-table'></i> Permissions Matrix</h2>")
  [void]$matrixBuilder.Append("<button class='hero-button' onclick='exportPermissionsMatrix()' style='background-color: var(--accent-color); margin: 0;'>")
  [void]$matrixBuilder.Append("<i class='fas fa-file-csv'></i> Export Matrix to CSV")
  [void]$matrixBuilder.Append("</button>")
  [void]$matrixBuilder.Append("</div>")
  [void]$matrixBuilder.Append("<div class='permissions-matrix-container'>")
  [void]$matrixBuilder.Append("<table class='permissions-matrix-table'>")
  [void]$matrixBuilder.Append("<thead><tr><th>Permission</th>")

  # Role names are already sorted in $script:allRoleNamesForMatrixData by Get-RolesWithScopeTags
  foreach ($roleName in $script:allRoleNamesForMatrixData) {
    [void]$matrixBuilder.Append("<th>$($roleName)</th>")
  }
  [void]$matrixBuilder.Append("</tr></thead>")
  [void]$matrixBuilder.Append("<tbody>")

  # Sort permission names for row display
  $sortedPermissionNames = $script:allPermissionsMatrixData.Keys | Sort-Object

  foreach ($permissionName in $sortedPermissionNames) {
    [void]$matrixBuilder.Append("<tr><td>$($permissionName)</td>")
    foreach ($roleName in $script:allRoleNamesForMatrixData) {
      # Use the sorted list for column order
      $hasPermission = $script:allPermissionsMatrixData[$permissionName].ContainsKey($roleName) -and $script:allPermissionsMatrixData[$permissionName][$roleName]
      $cellContent = if ($hasPermission) { "<span class='permission-check'>✔️</span>" } else { "<span class='permission-no'></span>" }
      [void]$matrixBuilder.Append("<td>$cellContent</td>")
    }
    [void]$matrixBuilder.Append("</tr>")
  }
  [void]$matrixBuilder.Append("</tbody></table></div>")
  
  Write-Host "Permissions matrix table built successfully" -ForegroundColor Green
  return $matrixBuilder.ToString()
}

# Fetch Scope Tags
Write-Host "Fetching scope tags..." -ForegroundColor Yellow
$scopeTagsUri = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags"
$scopeTags = Get-ScopeTags -Uri $scopeTagsUri
Write-Host "Retrieved $($scopeTags.Count) scope tags" -ForegroundColor Green

# Fetch Roles with Scope Tags
Write-Host "Fetching RBAC roles and analyzing permissions..." -ForegroundColor Yellow
$rolesUri = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions"
$htmlRolesWithScopeTags = Get-RolesWithScopeTags -Uri $rolesUri -ScopeTags $scopeTags
Write-Host "Completed RBAC role analysis" -ForegroundColor Green

# Calculate total number of roles
$totalRolesCount = $rolesWithScopeTagsCount + $rolesWithoutScopeTagsCount

# Get the number of scope tags
$scopeTagsCount = $scopeTags.Count

Write-Host "Found $totalRolesCount total roles ($customRolesCount custom, $builtInRolesCount built-in)" -ForegroundColor Cyan
Write-Host "Identified $unusedRolesCount unused roles and $rolesWithOverlappingPermissionsCount roles with overlapping permissions" -ForegroundColor Cyan

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
        <a href="#security-review-section" class="hero-button">
          <i class="fas fa-clipboard-check"></i> Security Review
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

/* Dark mode variables */
[data-theme="dark"] {
  --primary-color: #E0E0E0;
  --primary-light: #5CBA97;
  --primary-dark: #FFFFFF;
  --secondary-color: #00D9FF;
  --secondary-dark: #00B2CA;
  --accent-color: #5CBA97;
  --accent-light: #7ACFB6;
  --background-color: #1A1B2E;
  --surface-color: #2D3047;
  --text-color: #E0E0E0;
  --card-background: #242538;
  --border-color: #3A3C52;
  --error-color: #FF6B94;
  --warning-color: #FFB347;
  --info-color: #5CACFF;
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

/* Global Search Styles */
.global-search-container {
  position: relative;
  display: flex;
  justify-content: center;
  width: 100%;
  max-width: 600px;
  margin: 20px auto;
}

.global-search-input {
  width: 100%;
  padding: 12px 20px;
  padding-right: 50px;
  font-size: 16px;
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-radius: 30px;
  background-color: rgba(255, 255, 255, 0.15);
  color: white;
  transition: all 0.3s ease;
  backdrop-filter: blur(10px);
}

.global-search-input::placeholder {
  color: rgba(255, 255, 255, 0.7);
}

.global-search-input:focus {
  outline: none;
  background-color: rgba(255, 255, 255, 0.25);
  border-color: rgba(255, 255, 255, 0.5);
  box-shadow: 0 0 20px rgba(255, 255, 255, 0.2);
}

.clear-search-btn {
  position: absolute;
  right: 10px;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  color: white;
  padding: 5px 10px;
  cursor: pointer;
  font-size: 18px;
  transition: opacity 0.3s ease;
}

.clear-search-btn:hover {
  opacity: 0.8;
}

.search-results-count {
  text-align: center;
  color: white;
  margin-bottom: 15px;
  font-size: 14px;
  opacity: 0.9;
}

.search-highlight {
  background-color: #FFD700;
  color: #000;
  padding: 2px 4px;
  border-radius: 3px;
  font-weight: bold;
}

[data-theme="dark"] .search-highlight {
  background-color: #FFB347;
  color: #1A1B2E;
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
.security-badge.risk-critical {
  background-color: var(--error-color);
  color: white;
}
.security-badge.risk-high {
  background-color: #FF6B35;
  color: white;
}
.security-badge.risk-medium {
  background-color: #F7931E;
  color: white;
}
.security-badge.risk-low {
  background-color: #27AE60;
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

/* Dark Mode Toggle Button */
.dark-mode-toggle {
  position: fixed;
  top: 20px;
  right: 20px;
  z-index: 1000;
  background-color: var(--surface-color);
  color: var(--text-color);
  border: 2px solid var(--border-color);
  border-radius: 50%;
  width: 50px;
  height: 50px;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  transition: all 0.3s ease;
}

.dark-mode-toggle:hover {
  background-color: var(--primary-color);
  color: white;
  border-color: var(--primary-color);
  transform: scale(1.1);
}

.dark-mode-toggle i {
  font-size: 20px;
}

[data-theme="dark"] .dark-mode-toggle {
  background-color: var(--surface-color);
  border-color: var(--accent-color);
}

[data-theme="dark"] .dark-mode-toggle:hover {
  background-color: var(--accent-color);
  border-color: var(--accent-color);
}
</style>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
<button class="dark-mode-toggle" onclick="toggleDarkMode()" title="Toggle Dark Mode">
  <i class="fas fa-moon" id="darkModeIcon"></i>
</button>
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
      <div class="global-search-container">
        <input type="text" id="globalSearchInput" placeholder="Search roles and permissions..." class="global-search-input" onkeyup="performGlobalSearch()">
        <button onclick="clearGlobalSearch()" class="clear-search-btn" id="clearSearchBtn" style="display:none;">
          <i class="fas fa-times"></i>
        </button>
      </div>
      <div id="searchResultsCount" class="search-results-count" style="display:none;"></div>
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
    
    <div style='display: flex; justify-content: space-between; align-items: center;'>
      <h2 id='security-analysis-section' style='margin: 0;'><i class='fas fa-shield-alt'></i>Security Analysis</h2>
      <button class='hero-button' onclick='exportSecurityAnalysis()' style='background-color: var(--accent-color); margin: 0;'>
        <i class='fas fa-file-csv'></i> Export Security Analysis
      </button>
    </div>
    <div class='stats-grid' style='margin-top: 20px;'>
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
  <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;'>
    <h2 style='margin: 0;'><i class='fas fa-user-cog'></i> Roles Overview</h2>
    <button class='hero-button' onclick='exportRolesData()' style='background-color: var(--accent-color); margin: 0;'>
      <i class='fas fa-file-csv'></i> Export Roles to CSV
    </button>
  </div>
</div>
"@

$htmlFooter = @'
</div>
<footer class="footer">
    <div class="footer-content">
        <p class="footer-text">Created by <a href="https://www.linkedin.com/in/ugurkocde/" target="_blank" class="footer-link">Ugur Koc</a></p>
    </div>
</footer>
<script>
// Dark mode functionality
function toggleDarkMode() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateDarkModeButton(newTheme);
}

function updateDarkModeButton(theme) {
    const icon = document.getElementById('darkModeIcon');
    const button = document.querySelector('.dark-mode-toggle');
    if (theme === 'dark') {
        icon.className = 'fas fa-sun';
        button.title = 'Switch to Light Mode';
    } else {
        icon.className = 'fas fa-moon';
        button.title = 'Switch to Dark Mode';
    }
}

// Apply saved theme on load
document.addEventListener('DOMContentLoaded', (event) => {
    // Apply saved theme
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateDarkModeButton(savedTheme);

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
                // Set active tab to "All Permissions" if it exists
                var permTab = panel.querySelector('.permission-tab');
                if (permTab) {
                    permTab.classList.add('active');
                }
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

// CSV Export functionality
function exportToCSV(data, filename) {
    const csv = convertToCSV(data);
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    if (link.download !== undefined) {
        const url = URL.createObjectURL(blob);
        link.setAttribute('href', url);
        link.setAttribute('download', filename);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }
}

function convertToCSV(data) {
    if (!data || data.length === 0) return '';
    
    const headers = Object.keys(data[0]);
    const csvHeaders = headers.join(',');
    
    const csvRows = data.map(row => {
        return headers.map(header => {
            const value = row[header] || '';
            // Escape quotes and wrap in quotes if contains comma, newline, or quotes
            const escaped = String(value).replace(/"/g, '""');
            return /[",\n]/.test(escaped) ? `"${escaped}"` : escaped;
        }).join(',');
    });
    
    return [csvHeaders, ...csvRows].join('\n');
}

function exportRolesData() {
    const rolesData = [];
    document.querySelectorAll('.accordion').forEach(accordion => {
        const roleTitle = accordion.querySelector('.accordion-title').textContent;
        const panel = accordion.nextElementSibling;
        
        // Extract basic info
        const basicInfo = panel.querySelector('.panel-top-section');
        let description = '';
        let type = '';
        let scopeTag = '';
        
        if (basicInfo) {
            const paragraphs = basicInfo.querySelectorAll('p');
            paragraphs.forEach(p => {
                const text = p.textContent;
                if (text.includes('Description:')) description = text.replace('Description:', '').trim();
                if (text.includes('Type:')) type = text.replace('Type:', '').trim();
            });
            
            const scopeTagEl = basicInfo.querySelector('.scope-tag, .no-scope-tag');
            if (scopeTagEl) {
                scopeTag = scopeTagEl.textContent.replace('Scope Tag:', '').replace('No Scope Tag assigned', 'None').trim();
            }
        }
        
        // Extract assignment info
        let assignmentCount = 0;
        let groupNames = [];
        const assignmentSection = Array.from(panel.querySelectorAll('.panel-top-section')).find(section => 
            section.querySelector('h3')?.textContent.includes('Role Assignments')
        );
        
        if (assignmentSection) {
            const groups = assignmentSection.querySelectorAll('p');
            groups.forEach(p => {
                if (p.textContent.includes('Group:')) {
                    groupNames.push(p.textContent.replace('Group:', '').trim());
                }
            });
            assignmentCount = groupNames.length;
        }
        
        // Count permissions
        const permissionItems = panel.querySelectorAll('.permission-item');
        const permissionCount = permissionItems.length;
        
        // Check security badges
        const isUnused = accordion.querySelector('.security-badge.warning')?.textContent.includes('Unused') || false;
        const hasOverlapping = accordion.querySelector('.security-badge.info')?.textContent.includes('Overlapping') || false;
        
        rolesData.push({
            'Role Name': roleTitle,
            'Type': type,
            'Description': description,
            'Scope Tags': scopeTag,
            'Assignment Count': assignmentCount,
            'Groups': groupNames.join('; '),
            'Permission Count': permissionCount,
            'Is Unused': isUnused ? 'Yes' : 'No',
            'Has Overlapping Permissions': hasOverlapping ? 'Yes' : 'No'
        });
    });
    
    exportToCSV(rolesData, 'intune_rbac_roles_export.csv');
}

function exportPermissionsMatrix() {
    const matrixData = [];
    const table = document.querySelector('.permissions-matrix-table');
    if (!table) return;
    
    // Get headers (role names)
    const headers = Array.from(table.querySelectorAll('thead th')).map(th => th.textContent);
    
    // Get rows
    table.querySelectorAll('tbody tr').forEach(row => {
        const cells = row.querySelectorAll('td');
        const rowData = {};
        
        cells.forEach((cell, index) => {
            if (index === 0) {
                rowData['Permission'] = cell.textContent;
            } else {
                const hasPermission = cell.querySelector('.permission-check') ? 'Yes' : 'No';
                rowData[headers[index]] = hasPermission;
            }
        });
        
        matrixData.push(rowData);
    });
    
    exportToCSV(matrixData, 'intune_rbac_permissions_matrix.csv');
}

function exportSecurityAnalysis() {
    const securityData = [];
    
    // Get statistics from stat cards
    const statCards = document.querySelectorAll('.stat-card');
    let unusedRoles = 0;
    let overlappingRoles = 0;
    
    statCards.forEach(card => {
        const label = card.querySelector('.stat-label')?.textContent || '';
        const value = card.querySelector('.stat-number')?.textContent || '0';
        
        if (label.includes('Unused Roles')) unusedRoles = parseInt(value);
        if (label.includes('Overlapping Permissions')) overlappingRoles = parseInt(value);
    });
    
    // Collect unused roles
    document.querySelectorAll('.accordion').forEach(accordion => {
        const roleTitle = accordion.querySelector('.accordion-title').textContent;
        const isUnused = accordion.querySelector('.security-badge.warning')?.textContent.includes('Unused') || false;
        const hasOverlapping = accordion.querySelector('.security-badge.info')?.textContent.includes('Overlapping') || false;
        
        if (isUnused || hasOverlapping) {
            const panel = accordion.nextElementSibling;
            let issues = [];
            if (isUnused) issues.push('Unused Role');
            if (hasOverlapping) issues.push('Overlapping Permissions');
            
            // Get overlap details if available
            let overlapDetails = '';
            const overlapSection = panel.querySelector('.overlap-list');
            if (overlapSection) {
                const overlaps = Array.from(overlapSection.querySelectorAll('li')).map(li => li.textContent);
                overlapDetails = overlaps.join('; ');
            }
            
            securityData.push({
                'Role Name': roleTitle,
                'Security Issues': issues.join(', '),
                'Details': overlapDetails || 'No group assignments'
            });
        }
    });
    
    exportToCSV(securityData, 'intune_rbac_security_analysis.csv');
}

// Global Search functionality
let originalContent = {};
let searchActive = false;

function performGlobalSearch() {
    const searchInput = document.getElementById('globalSearchInput');
    const searchTerm = searchInput.value.toLowerCase().trim();
    const clearBtn = document.getElementById('clearSearchBtn');
    const resultsCount = document.getElementById('searchResultsCount');
    
    if (searchTerm.length === 0) {
        clearGlobalSearch();
        return;
    }
    
    clearBtn.style.display = 'inline-block';
    searchActive = true;
    
    let totalMatches = 0;
    const accordions = document.querySelectorAll('.accordion');
    
    accordions.forEach((accordion, index) => {
        const panel = accordion.nextElementSibling;
        let matchFound = false;
        
        // Save original content if not already saved
        if (!originalContent[index]) {
            originalContent[index] = {
                accordion: accordion.innerHTML,
                panel: panel.innerHTML
            };
        }
        
        // Restore original content before applying new search
        if (originalContent[index]) {
            accordion.innerHTML = originalContent[index].accordion;
            panel.innerHTML = originalContent[index].panel;
            // Re-attach event listeners to restored content
            reattachPermissionListeners(panel);
        }
        
        // Search in role title
        const roleTitle = accordion.querySelector('.accordion-title').textContent.toLowerCase();
        if (roleTitle.includes(searchTerm)) {
            matchFound = true;
            // Highlight the match in role title
            const titleElement = accordion.querySelector('.accordion-title');
            titleElement.innerHTML = highlightText(titleElement.textContent, searchTerm);
        }
        
        // Search only in permissions
        let permissionFound = false;
        panel.querySelectorAll('.permission-name').forEach(element => {
            if (element.textContent.toLowerCase().includes(searchTerm)) {
                permissionFound = true;
                element.innerHTML = highlightText(element.textContent, searchTerm);
            }
        });
        
        if (permissionFound) {
            matchFound = true;
        }
        
        if (matchFound) {
            totalMatches++;
            accordion.style.display = '';
            panel.style.display = '';
            
            // Auto-expand matching panels
            if (!accordion.classList.contains('active')) {
                accordion.classList.add('active');
                panel.classList.add('active');
                panel.style.maxHeight = panel.scrollHeight + "px";
                
                // Show all permission categories in expanded panels
                panel.querySelectorAll('.permission-category').forEach(cat => {
                    cat.style.display = 'block';
                });
            }
        } else {
            accordion.style.display = 'none';
            panel.style.display = 'none';
        }
    });
    
    // Update results count
    if (totalMatches > 0) {
        resultsCount.textContent = `Found ${totalMatches} role${totalMatches > 1 ? 's' : ''} matching "${searchTerm}"`;
        resultsCount.style.display = 'block';
    } else {
        resultsCount.textContent = `No results found for "${searchTerm}"`;
        resultsCount.style.display = 'block';
    }
    
    // Also search in permissions matrix if visible
    searchInPermissionsMatrix(searchTerm);
}

function highlightText(text, searchTerm) {
    const regex = new RegExp(`(${escapeRegExp(searchTerm)})`, 'gi');
    return text.replace(regex, '<span class="search-highlight">$1</span>');
}

function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function clearGlobalSearch() {
    const searchInput = document.getElementById('globalSearchInput');
    const clearBtn = document.getElementById('clearSearchBtn');
    const resultsCount = document.getElementById('searchResultsCount');
    
    searchInput.value = '';
    clearBtn.style.display = 'none';
    resultsCount.style.display = 'none';
    searchActive = false;
    
    // Restore original content
    const accordions = document.querySelectorAll('.accordion');
    accordions.forEach((accordion, index) => {
        if (originalContent[index]) {
            accordion.innerHTML = originalContent[index].accordion;
            const panel = accordion.nextElementSibling;
            panel.innerHTML = originalContent[index].panel;
            
            // Re-attach event listeners to restored content
            reattachPermissionListeners(panel);
        }
        
        accordion.style.display = '';
        accordion.nextElementSibling.style.display = '';
        
        // Collapse all panels
        accordion.classList.remove('active');
        const panel = accordion.nextElementSibling;
        panel.classList.remove('active');
        panel.style.maxHeight = null;
    });
    
    // Clear matrix search
    clearMatrixSearch();
    
    // Clear saved content
    originalContent = {};
}

function reattachPermissionListeners(panel) {
    // Re-attach search functionality
    const searchInput = panel.querySelector('.permission-search');
    if (searchInput) {
        searchInput.onkeyup = function() { filterPermissions(this); };
    }
    
    // Re-attach tab functionality
    panel.querySelectorAll('.permission-tab').forEach(tab => {
        tab.onclick = function() { showCategory(this, tab.textContent.includes('All') ? 'all' : tab.textContent); };
    });
}

function searchInPermissionsMatrix(searchTerm) {
    const table = document.querySelector('.permissions-matrix-table');
    if (!table) return;
    
    // First, clear any existing highlights
    clearMatrixSearch();
    
    // Search in table cells
    table.querySelectorAll('td, th').forEach(cell => {
        if (cell.textContent.toLowerCase().includes(searchTerm)) {
            cell.innerHTML = highlightText(cell.textContent, searchTerm);
        }
    });
}

function clearMatrixSearch() {
    const table = document.querySelector('.permissions-matrix-table');
    if (!table) return;
    
    // Remove highlights from matrix
    table.querySelectorAll('.search-highlight').forEach(highlight => {
        const parent = highlight.parentNode;
        parent.replaceChild(document.createTextNode(highlight.textContent), highlight);
        parent.normalize();
    });
}

// Add keyboard shortcut for search (Ctrl+F or Cmd+F)
document.addEventListener('keydown', function(e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
        e.preventDefault();
        document.getElementById('globalSearchInput').focus();
    }
});
</script>
</body>
</html>
'@

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

  var originalNodesState = {}; // To store original color/size for reset

  document.addEventListener('DOMContentLoaded', function() {
    if (graphNodes.length > 0) {
      drawRoleGraph();
      // Initialize original node states after graph is drawn
      allNodesDataset.getIds().forEach(function(nodeId){
        var node = allNodesDataset.get(nodeId);
        originalNodesState[nodeId] = { color: node.color, size: node.size };
      });
    } else {
      document.getElementById('roleGraphVisualization').innerHTML = '<p style="text-align:center;padding-top:20px;">No data available to display the relationship diagram.</p>';
    }
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

# Optimize HTML size function
function Optimize-HtmlSize {
  param([string]$Html)
    
  Write-Host "Optimizing HTML output size..." -ForegroundColor Yellow
    
  # Remove HTML comments (but not JavaScript comments)
  $optimized = $Html -replace '<!--.*?-->', ''
    
  # Don't optimize inside script tags to preserve JavaScript
  $scriptPattern = '(?s)<script[^>]*>.*?</script>'
  $scripts = @()
  $scriptIndex = 0
    
  # Extract scripts to preserve them
  $optimized = [regex]::Replace($optimized, $scriptPattern, {
    param($match)
    $script:scripts += $match.Value
    "###SCRIPT_PLACEHOLDER_$($script:scriptIndex)###"
    $script:scriptIndex++
  })
    
  # Compress whitespace between tags (but not in scripts)
  $optimized = $optimized -replace '>\s+<', '><'
    
  # Remove unnecessary whitespace (but preserve single spaces)
  $optimized = $optimized -replace '\s{2,}', ' '
    
  # Restore scripts
  for ($i = 0; $i -lt $script:scripts.Count; $i++) {
    $optimized = $optimized -replace "###SCRIPT_PLACEHOLDER_$i###", $script:scripts[$i]
  }
    
  return $optimized
}

function Generate-SecurityReviewHtml {
  Write-Host "Building Security Review dashboard..." -ForegroundColor Yellow
  
  # Prepare role data
  $roleDataArray = @()
  foreach ($roleId in $script:securityReviewData.RoleRiskScores.Keys) {
    $roleDataArray += $script:securityReviewData.RoleRiskScores[$roleId]
  }
  
  # Generate recommendations
  $recommendations = Get-SecurityRecommendations -roleData $roleDataArray
  
  # Calculate overall health score
  $healthScore = Calculate-OverallHealthScore -roleData $roleDataArray
  
  # Build HTML
  $reviewBuilder = [System.Text.StringBuilder]::new()
  
  # Security Review Header
  [void]$reviewBuilder.Append(@"
<div id='security-review-section' class='container-section'>
  <h2><i class='fas fa-clipboard-check'></i> Security Review Dashboard</h2>
  
  <!-- Overall Health Score -->
  <div class='security-health-score'>
    <div class='health-score-container'>
      <div class='health-score-circle' data-score='$($healthScore.Score)'>
        <svg viewBox='0 0 200 200'>
          <circle cx='100' cy='100' r='90' fill='none' stroke='#e0e0e0' stroke-width='20'/>
          <circle cx='100' cy='100' r='90' fill='none' stroke='$(Get-HealthScoreColor -score $healthScore.Score)' 
                  stroke-width='20' stroke-dasharray='$(565.48 * $healthScore.Score / 100) 565.48' 
                  stroke-dashoffset='0' transform='rotate(-90 100 100)'/>
        </svg>
        <div class='health-score-text'>
          <span class='health-score-number'>$($healthScore.Score)</span>
          <span class='health-score-grade'>Grade: $($healthScore.Grade)</span>
        </div>
      </div>
      <div class='health-score-details'>
        <h3>Security Health Score</h3>
        <p>Your overall RBAC security posture score based on risk assessment and security best practices.</p>
        <div class='score-deductions'>
          <h4>Score Breakdown:</h4>
          <ul>
"@)
  
  foreach ($deduction in $healthScore.Deductions.GetEnumerator()) {
    if ($deduction.Value -gt 0) {
      [void]$reviewBuilder.Append("<li>$($deduction.Key): -$($deduction.Value) points</li>")
    }
  }
  
  [void]$reviewBuilder.Append(@"
          </ul>
        </div>
      </div>
    </div>
  </div>
  
  <!-- Risk Distribution -->
  <div class='risk-distribution'>
    <h3><i class='fas fa-chart-pie'></i> Risk Distribution</h3>
    <div class='risk-stats-grid'>
"@)
  
  # Calculate risk distribution
  $riskLevels = @{
    Critical = ($roleDataArray | Where-Object { $_.RiskScore.Level -eq "Critical" }).Count
    High = ($roleDataArray | Where-Object { $_.RiskScore.Level -eq "High" }).Count
    Medium = ($roleDataArray | Where-Object { $_.RiskScore.Level -eq "Medium" }).Count
    Low = ($roleDataArray | Where-Object { $_.RiskScore.Level -eq "Low" }).Count
  }
  
  foreach ($level in @("Critical", "High", "Medium", "Low")) {
    $count = $riskLevels[$level]
    $percentage = if ($roleDataArray.Count -gt 0) { [Math]::Round(($count / $roleDataArray.Count) * 100, 1) } else { 0 }
    $colorClass = "risk-$($level.ToLower())"
    
    [void]$reviewBuilder.Append(@"
      <div class='risk-stat-card $colorClass'>
        <div class='risk-stat-icon'><i class='fas fa-shield-alt'></i></div>
        <div class='risk-stat-number'>$count</div>
        <div class='risk-stat-label'>$level Risk</div>
        <div class='risk-stat-percentage'>$percentage%</div>
      </div>
"@)
  }
  
  [void]$reviewBuilder.Append(@"
    </div>
  </div>
  
  <!-- Top Risk Roles -->
  <div class='top-risk-roles'>
    <h3><i class='fas fa-exclamation-triangle'></i> Highest Risk Roles</h3>
    <div class='risk-roles-table'>
      <table>
        <thead>
          <tr>
            <th>Role Name</th>
            <th>Risk Score</th>
            <th>Risk Level</th>
            <th>Users</th>
            <th>Critical Permissions</th>
          </tr>
        </thead>
        <tbody>
"@)
  
  # Get top 10 highest risk roles
  $topRiskRoles = $roleDataArray | Sort-Object { $_.RiskScore.TotalScore } -Descending | Select-Object -First 10
  
  foreach ($role in $topRiskRoles) {
    $riskClass = "risk-$($role.RiskScore.Level.ToLower())"
    [void]$reviewBuilder.Append(@"
          <tr>
            <td>$($role.DisplayName)</td>
            <td><span class='risk-score-badge $riskClass'>$($role.RiskScore.TotalScore)</span></td>
            <td><span class='risk-level-badge $riskClass'>$($role.RiskScore.Level)</span></td>
            <td>$($role.UserCount)</td>
            <td>$($role.RiskScore.CriticalPermissionCount)</td>
          </tr>
"@)
  }
  
  [void]$reviewBuilder.Append(@"
        </tbody>
      </table>
    </div>
  </div>
  
  <!-- Security Recommendations -->
  <div class='security-recommendations'>
    <div style='display: flex; justify-content: space-between; align-items: center;'>
      <h3><i class='fas fa-lightbulb'></i> Security Recommendations</h3>
      <button class='hero-button' onclick='exportSecurityReview()' style='background-color: var(--accent-color); margin: 0;'>
        <i class='fas fa-file-pdf'></i> Export Security Review
      </button>
    </div>
    <div class='recommendations-list'>
"@)
  
  # Group recommendations by priority
  $priorityGroups = $recommendations | Group-Object -Property Priority
  
  foreach ($priority in @("High", "Medium", "Low")) {
    $group = $priorityGroups | Where-Object { $_.Name -eq $priority }
    if ($group) {
      [void]$reviewBuilder.Append("<div class='priority-group priority-$($priority.ToLower())'>")
      [void]$reviewBuilder.Append("<h4><i class='fas fa-flag'></i> $priority Priority</h4>")
      
      foreach ($rec in $group.Group) {
        [void]$reviewBuilder.Append(@"
        <div class='recommendation-card'>
          <div class='rec-header'>
            <span class='rec-role'>$($rec.RoleName)</span>
            <span class='rec-category'>$($rec.Category)</span>
          </div>
          <p class='rec-text'>$($rec.Recommendation)</p>
          <p class='rec-impact'><i class='fas fa-info-circle'></i> Impact: $($rec.Impact)</p>
        </div>
"@)
      }
      [void]$reviewBuilder.Append("</div>")
    }
  }
  
  [void]$reviewBuilder.Append(@"
    </div>
  </div>
</div>

<style>
/* Security Review Styles */
.security-health-score {
  background-color: var(--surface-color);
  border-radius: 10px;
  padding: 30px;
  margin: 20px 0;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.health-score-container {
  display: flex;
  align-items: center;
  gap: 40px;
}

.health-score-circle {
  position: relative;
  width: 200px;
  height: 200px;
}

.health-score-circle svg {
  width: 100%;
  height: 100%;
}

.health-score-text {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  text-align: center;
}

.health-score-number {
  display: block;
  font-size: 3em;
  font-weight: bold;
  color: var(--primary-color);
}

.health-score-grade {
  display: block;
  font-size: 1.2em;
  color: var(--text-color);
}

.score-deductions ul {
  list-style: none;
  padding-left: 0;
}

.score-deductions li {
  padding: 5px 0;
  color: var(--text-color);
}

.risk-distribution, .top-risk-roles, .security-recommendations {
  background-color: var(--surface-color);
  border-radius: 10px;
  padding: 25px;
  margin: 20px 0;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.risk-stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 20px;
  margin-top: 20px;
}

.risk-stat-card {
  text-align: center;
  padding: 20px;
  border-radius: 8px;
  transition: transform 0.3s;
}

.risk-stat-card:hover {
  transform: translateY(-5px);
}

.risk-stat-card.risk-critical {
  background-color: rgba(239, 71, 111, 0.1);
  border: 2px solid var(--error-color);
}

.risk-stat-card.risk-high {
  background-color: rgba(255, 107, 53, 0.1);
  border: 2px solid #FF6B35;
}

.risk-stat-card.risk-medium {
  background-color: rgba(247, 147, 30, 0.1);
  border: 2px solid #F7931E;
}

.risk-stat-card.risk-low {
  background-color: rgba(39, 174, 96, 0.1);
  border: 2px solid #27AE60;
}

.risk-stat-icon {
  font-size: 2em;
  margin-bottom: 10px;
}

.risk-stat-number {
  font-size: 2.5em;
  font-weight: bold;
}

.risk-stat-percentage {
  font-size: 0.9em;
  color: var(--text-color);
  opacity: 0.8;
}

.risk-roles-table table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 20px;
}

.risk-roles-table th,
.risk-roles-table td {
  padding: 12px;
  text-align: left;
  border-bottom: 1px solid var(--border-color);
}

.risk-score-badge, .risk-level-badge {
  padding: 4px 8px;
  border-radius: 4px;
  font-weight: bold;
  font-size: 0.9em;
}

.risk-score-badge.risk-critical,
.risk-level-badge.risk-critical {
  background-color: var(--error-color);
  color: white;
}

.risk-score-badge.risk-high,
.risk-level-badge.risk-high {
  background-color: #FF6B35;
  color: white;
}

.risk-score-badge.risk-medium,
.risk-level-badge.risk-medium {
  background-color: #F7931E;
  color: white;
}

.risk-score-badge.risk-low,
.risk-level-badge.risk-low {
  background-color: #27AE60;
  color: white;
}


.recommendations-list {
  margin-top: 20px;
}

.priority-group {
  margin-bottom: 30px;
}

.priority-group h4 {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 15px;
}

.recommendation-card {
  background-color: var(--card-background);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 15px;
  margin-bottom: 15px;
}

.rec-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 10px;
}

.rec-role {
  font-weight: bold;
  color: var(--primary-color);
}

.rec-category {
  background-color: var(--surface-color);
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 0.8em;
}

.rec-text {
  margin: 10px 0;
  color: var(--text-color);
}

.rec-impact {
  font-size: 0.9em;
  color: var(--text-color);
  opacity: 0.8;
}
</style>

<script>
function exportSecurityReview() {
    // Prepare security review data
    const reviewData = {
        generatedDate: new Date().toISOString(),
        healthScore: $($healthScore.Score),
        grade: '$($healthScore.Grade)',
        riskDistribution: $(ConvertTo-Json $riskLevels -Compress),
        recommendations: $(ConvertTo-Json $recommendations -Compress)
    };
    
    // Create CSV data
    const csvData = [];
    
    // Add summary
    csvData.push({
        'Category': 'Overall Health Score',
        'Value': reviewData.healthScore,
        'Details': 'Grade: ' + reviewData.grade
    });
    
    // Add risk distribution
    Object.entries(reviewData.riskDistribution).forEach(([level, count]) => {
        csvData.push({
            'Category': 'Risk Distribution',
            'Value': level,
            'Details': count + ' roles'
        });
    });
    
    // Add recommendations
    reviewData.recommendations.forEach(rec => {
        csvData.push({
            'Category': 'Recommendation',
            'Value': rec.RoleName,
            'Details': rec.Recommendation + ' (Priority: ' + rec.Priority + ')'
        });
    });
    
    exportToCSV(csvData, 'intune_security_review_export.csv');
}

function getHealthScoreColor(score) {
    if (score >= 80) return '#27AE60';
    if (score >= 60) return '#F7931E';
    if (score >= 40) return '#FF6B35';
    return '#EF476F';
}
</script>
"@)
  
  Write-Host "Security Review dashboard built successfully" -ForegroundColor Green
  return $reviewBuilder.ToString()
}

function Get-HealthScoreColor {
  param($score)
  
  if ($score -ge 80) { return "#27AE60" }
  if ($score -ge 60) { return "#F7931E" }
  if ($score -ge 40) { return "#FF6B35" }
  return "#EF476F"
}

# Combine HTML content and save to file
Write-Host "Generating permissions matrix..." -ForegroundColor Yellow
$permissionsMatrixHtml = Generate-PermissionsMatrixHtml
Write-Host "Permissions matrix generated successfully" -ForegroundColor Green

Write-Host "Creating interactive role relationship diagram..." -ForegroundColor Yellow
$roleRelationshipDiagramHtml = Generate-RoleRelationshipDiagramHtml -Nodes $script:graphNodes -Links $script:graphLinks
Write-Host "Role relationship diagram created successfully" -ForegroundColor Green

Write-Host "Generating Security Review dashboard..." -ForegroundColor Yellow
$securityReviewHtml = Generate-SecurityReviewHtml
Write-Host "Security Review dashboard generated successfully" -ForegroundColor Green

Write-Host "Assembling final HTML report..." -ForegroundColor Yellow
$htmlComplete = $htmlHeader + $htmlRolesOverviewHeader + $htmlRolesWithScopeTags + $permissionsMatrixHtml + $roleRelationshipDiagramHtml + $securityReviewHtml + $htmlFooter

# Skip HTML optimization for now as it's breaking JavaScript
# $htmlComplete = Optimize-HtmlSize -Html $htmlComplete

# Save the HTML file with full path
$reportFileName = "rbachealthcheck.html"
$reportFilePath = Join-Path -Path (Get-Location).Path -ChildPath $reportFileName
$htmlComplete | Out-File $reportFilePath

Write-Host "HTML report saved to '$reportFilePath'" -ForegroundColor Green
Write-Host "RBAC Health Check completed successfully!" -ForegroundColor Cyan

# Offer to open the HTML report
$openReport = Read-Host "Would you like to open the HTML report now? (Y/N)"
if ($openReport -eq "Y" -or $openReport -eq "y") {
  Write-Host "Opening HTML report..." -ForegroundColor Yellow
  try {
    Invoke-Item $reportFilePath
    Write-Host "Report opened successfully" -ForegroundColor Green
  }
  catch {
    Write-Host "Could not open the report automatically. Please open it manually from: $reportFilePath" -ForegroundColor Red
  }
}