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
            #Description = $scopeTag.description
        }
    }

    return $scopeTagDetails
}

# Step 3: Function to Fetch Mobile Apps and their Scope Tags
function Get-MobileAppDetails {
    param($ScopeTags)

    $mobileAppDetails = @()
    $Uri = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$filter=isAssigned eq true&$orderby=displayName&$top=100'

    do {
        $response = Invoke-MgGraphRequest -Uri $Uri -Method GET
        foreach ($app in $response.value) {
            # Additional request to fetch roleScopeTagIds for each app
            
            $appDetailsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($app.id)?$select=roleScopeTagIds"
            $appDetailsResponse = Invoke-MgGraphRequest -Uri $appDetailsUri -Method GET

            $scopeTagNames = @()
            foreach ($tagId in $appDetailsResponse.roleScopeTagIds) {
                if ($ScopeTags[$tagId]) {
                    $scopeTagNames += $ScopeTags[$tagId].DisplayName
                }
            }

            $mobileAppDetails += [PSCustomObject]@{
                Type       = "App"
                Name       = $appDetailsResponse.displayName
                Id         = $appDetailsResponse.id
                Assigned   = $appDetailsResponse.isAssigned
                RoleScopeTagIds = $appDetailsResponse.roleScopeTagIds -join ', '
                ScopeTags  = ($scopeTagNames -join ', ')
            }
        }
        $Uri = $response.'@odata.nextLink'
    } while ($Uri)

    return $mobileAppDetails
}