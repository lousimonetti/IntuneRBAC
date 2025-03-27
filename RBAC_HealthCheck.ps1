# Step 1: Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementRBAC.Read.All, DeviceManagementApps.Read.All, DeviceManagementConfiguration.Read.All, User.ReadBasic.All" -NoWelcome

# Get tenant information and timestamp
$tenantInfo = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization" -Method GET
$tenantName = $tenantInfo.value[0].displayName
$lastUpdated = Get-Date -Format "MMMM dd, yyyy HH:mm"
$version = "0.1"

# Data processing for charts
$rolesWithScopeTagsCount = 0
$rolesWithoutScopeTagsCount = 0
$customRolesCount = 0
$builtInRolesCount = 0

# Fetch all roles first
$rolesUri = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions"
$response = Invoke-MgGraphRequest -Uri $rolesUri -Method GET

# Process the roles for counting
foreach ($role in $response.value) {
    if ($role.roleScopeTagIds.Count -gt 0) {
        $rolesWithScopeTagsCount++
    } else {
        $rolesWithoutScopeTagsCount++
    }

    if ($role.isBuiltIn) {
        $builtInRolesCount++
    } else {
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
        'Mobile Apps' = @()
        'Managed Apps' = @()
        'Devices' = @()
        'Policies' = @()
        'Filters' = @()
        'Security' = @()
        'Other' = @()
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

# Function to Fetch Roles and their Scope Tags
function Get-RolesWithScopeTags {
    param(
        $Uri, 
        $ScopeTags
    )
    $response = Invoke-MgGraphRequest -Uri $Uri -Method GET

    $htmlContent = @()

    foreach ($role in $response.value) {
        $allowedActions = @()
        foreach ($perm in $role.rolePermissions) {
            foreach ($action in $perm.resourceActions) {
                $allowedActions += $action.allowedResourceActions
            }
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
        } else {
            $scopeTagInfo = "<div class='no-scope-tag'>No Scope Tag assigned</div>"
        }

        # Start the accordion for each role
        $htmlContent += "<button class='accordion'><strong>$($role.displayName)</strong></button>"
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
        $htmlContent += "</div>" # Close panel-top

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
    }

    return $htmlContent
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
  opacity: 0.1;
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
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
  margin-top: 20px;
}

.stat-card {
  background-color: var(--card-background);
  padding: 20px;
  border-radius: 8px;
  text-align: center;
  transition: transform 0.2s;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
  border: 1px solid var(--border-color);
}

.stat-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
}

.stat-number {
  font-size: 2.5em;
  font-weight: bold;
  color: var(--primary-color);
  margin: 10px 0;
}

.stat-label {
  color: var(--text-color);
  font-size: 1.1em;
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
  display: flex;
  justify-content: space-between;
  align-items: center;
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
      </div>
    </div>
  </div>
</div>
<div class="container">
  <!-- Statistics Section -->
  <div class='stats-container'>
    <h2>RBAC Statistics</h2>
    <div class='stats-grid'>
      <div class='stat-card'>
        <div class='stat-number'>$totalRolesCount</div>
        <div class='stat-label'>Total Intune Roles</div>
      </div>
      <div class='stat-card'>
        <div class='stat-number'>$customRolesCount</div>
        <div class='stat-label'>Custom Roles</div>
      </div>
      <div class='stat-card'>
        <div class='stat-number'>$scopeTagsCount</div>
        <div class='stat-label'>Scope Tags</div>
      </div>
    </div>
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

# Combine HTML content and save to file
$htmlComplete = $htmlHeader + ($htmlRolesWithScopeTags -join " ") + $htmlFooter
$htmlComplete | Out-File "rbachealthcheck.html"