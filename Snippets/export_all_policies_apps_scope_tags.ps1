# Step 1: Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementRBAC.Read.All, DeviceManagementApps.Read.All, DeviceManagementConfiguration.Read.All"

# Step 2: Function to Fetch Scope Tag Details
function Get-ScopeTagDetails {
    $Uri = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags"
    $scopeTagsResponse = Invoke-MgGraphRequest -Uri $Uri -Method GET

    $scopeTagDetails = @{}
    foreach ($scopeTag in $scopeTagsResponse.value) {
        $scopeTagDetails[$scopeTag.id] = @{
            DisplayName = $scopeTag.displayName
            Description = $scopeTag.description
        }
    }

    return $scopeTagDetails
}

# Step 3: Function to Fetch Device Configuration Details
function Get-DeviceConfigDetails {
    param($DeviceConfig, $ScopeTags)
    $Uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($DeviceConfig.id)"

    $response = Invoke-MgGraphRequest -Uri $Uri -Method GET

    $scopeTagNames = @()
    foreach ($tagId in $response.roleScopeTagIds) {
        if ($ScopeTags[$tagId]) {
            $scopeTagNames += $ScopeTags[$tagId].DisplayName
        }
    }

    [PSCustomObject]@{
        Type = "Device Configuration"
        Name = $DeviceConfig.displayName
        Id = $DeviceConfig.id
        RoleScopeTagIds = $response.roleScopeTagIds -join ', '
        ScopeTagNames = $scopeTagNames -join ', '
    }
}

# Step 4: Function to Fetch Device Compliance Policy Details
function Get-DeviceCompliancePolicyDetails {
    param($DeviceCompliancePolicy, $ScopeTags)
    $Uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$($DeviceCompliancePolicy.id)"

    $response = Invoke-MgGraphRequest -Uri $Uri -Method GET

    $scopeTagNames = @()
    foreach ($tagId in $response.roleScopeTagIds) {
        if ($ScopeTags[$tagId]) {
            $scopeTagNames += $ScopeTags[$tagId].DisplayName
        }
    }

    [PSCustomObject]@{
        Type = "Device Compliance Policy"
        Name = $DeviceCompliancePolicy.displayName
        Id = $DeviceCompliancePolicy.id
        RoleScopeTagIds = $response.roleScopeTagIds -join ', '
        ScopeTagNames = $scopeTagNames -join ', '
    }
}

# Step 5: Function to Fetch Device Shell Script Details
function Get-DeviceShellScriptDetails {
    param($DeviceShellScript, $ScopeTags)
    $Uri = "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts/$($DeviceShellScript.id)"

    $response = Invoke-MgGraphRequest -Uri $Uri -Method GET

    $scopeTagNames = @()
    foreach ($tagId in $response.roleScopeTagIds) {
        if ($ScopeTags[$tagId]) {
            $scopeTagNames += $ScopeTags[$tagId].DisplayName
        }
    }

    [PSCustomObject]@{
        Type = "Device Shell Script"
        Name = $DeviceShellScript.displayName
        Id = $DeviceShellScript.id
        RoleScopeTagIds = $response.roleScopeTagIds -join ', '
        ScopeTagNames = $scopeTagNames -join ', '
    }
}

# Step 6: Function to Fetch Configuration Policy Details
function Get-ConfigurationPolicyDetails {
    param($ConfigurationPolicy, $ScopeTags)
    $Uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($ConfigurationPolicy.id)')"

    $response = Invoke-MgGraphRequest -Uri $Uri -Method GET

    $scopeTagNames = @()
    foreach ($tagId in $response.roleScopeTagIds) {
        if ($ScopeTags[$tagId]) {
            $scopeTagNames += $ScopeTags[$tagId].DisplayName
        }
    }

    [PSCustomObject]@{
        Type = "Configuration Policy"
        Name = $ConfigurationPolicy.name
        Id = $ConfigurationPolicy.id
        RoleScopeTagIds = $response.roleScopeTagIds -join ', '
        ScopeTagNames = $scopeTagNames -join ', '
        Platform = $ConfigurationPolicy.platforms
    }
}

# Step 7: Function to Fetch Mobile App Details
<# function Get-MobileAppDetails {
    param($MobileApp, $ScopeTags)
    $Uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($MobileApp.id)"

    $response = Invoke-MgGraphRequest -Uri $Uri -Method GET

    # Check if the app has any assignments
    if ($response.assignments -and $response.assignments.Count -gt 0) {
        $scopeTagNames = @()
        foreach ($tagId in $response.roleScopeTagIds) {
            if ($ScopeTags[$tagId]) {
                $scopeTagNames += $ScopeTags[$tagId].DisplayName
            }
        }

        [PSCustomObject]@{
            Type = "Mobile App"
            Name = $MobileApp.displayName
            Id = $MobileApp.id
            RoleScopeTagIds = $response.roleScopeTagIds -join ', '
            ScopeTagNames = $scopeTagNames -join ', '
        }
    }
} #>


# Step 8: Fetch All Device Configurations, Compliance Policies, Shell Scripts, Configuration Policies, and Mobile Apps and Process Each
$scopeTags = Get-ScopeTagDetails

$deviceConfigUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
$deviceComplianceUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
$deviceShellScriptUri = "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts"
$configurationPolicyUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
#$mobileAppUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"

$configs = Invoke-MgGraphRequest -Uri $deviceConfigUri -Method GET
$compliances = Invoke-MgGraphRequest -Uri $deviceComplianceUri -Method GET
$shellScripts = Invoke-MgGraphRequest -Uri $deviceShellScriptUri -Method GET
$configurationPolicies = Invoke-MgGraphRequest -Uri $configurationPolicyUri -Method GET
#$mobileApps = Invoke-MgGraphRequest -Uri $mobileAppUri -Method GET

$results = @()

if ($configs.value) {
    foreach ($config in $configs.value) {
        $results += Get-DeviceConfigDetails -DeviceConfig $config -ScopeTags $scopeTags
    }
}

if ($compliances.value) {
    foreach ($compliance in $compliances.value) {
        $results += Get-DeviceCompliancePolicyDetails -DeviceCompliancePolicy $compliance -ScopeTags $scopeTags
    }
}

if ($shellScripts.value) {
    foreach ($script in $shellScripts.value) {
        $results += Get-DeviceShellScriptDetails -DeviceShellScript $script -ScopeTags $scopeTags
    }
}

if ($configurationPolicies.value) {
    foreach ($policy in $configurationPolicies.value) {
        $results += Get-ConfigurationPolicyDetails -ConfigurationPolicy $policy -ScopeTags $scopeTags
    }
}

<# if ($mobileApps.value) {
    foreach ($app in $mobileApps.value) {
        $results += Get-MobileAppDetails -MobileApp $app -ScopeTags $scopeTags
    }
} #>

$results | Format-List

# Uncomment the following line to view the output in a grid view and export to CSV
# $results | Out-GridView -PassThru -Title "Select Items to Export" | Export-Csv -Path "C:\Users\UgurKoc\Downloads\device_management_details.csv" -NoTypeInformation