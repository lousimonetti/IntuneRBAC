# Step 1: Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementRBAC.Read.All, DeviceManagementApps.Read.All, DeviceManagementConfiguration.Read.All"

# Step 2: Function to Fetch Devices and their Scope Tags
function Get-ManagedDevices {
    param($Uri)
    $devices = @()
    try {
        $response = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices" -Method GET

        foreach ($device in $response.value) {
            # Retrieve scope tags for the device
            $deviceDetailsResponse = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$($device.id)')" -Method GET
            $scopeTagIds = $deviceDetailsResponse.roleScopeTagIds

            # Fetch the display names of each scope tag
            $scopeTagNames = @()
            foreach ($tagId in $scopeTagIds) {
                $tagDetailsResponse = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags/$tagId" -Method GET
                $scopeTagNames += $tagDetailsResponse.displayName
            }

            $devices += New-Object PSObject -Property @{
                DeviceName = $device.deviceName  
                DeviceId = $device.id             
                ScopeTags = ($scopeTagNames -join ", ")
            }
        }

        # Recursively call for next link if available
        if ($response.'@odata.nextLink') {
            $devices += Get-ManagedDevices -Uri $response.'@odata.nextLink'
        }
    } catch {
        Write-Host "Error fetching devices: $($_.Exception.Message)"
    }

    $global:allDevices += $devices
    return $devices
}
