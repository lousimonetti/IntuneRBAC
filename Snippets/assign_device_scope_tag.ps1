# Step 1: Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementManagedDevices.ReadWrite.All, DeviceManagementRBAC.Read.All"

# Define the Scope Tag Name
$scopeTagName = "MacOS" # Replace with your actual scope tag name

# Step 2: Function to get Scope Tags
function Get-ScopeTags {
    param($Uri)
    $response = Invoke-MgGraphRequest -Uri $Uri -Method GET
    $response.value

    # Recursively call for next link if available
    if ($response.'@odata.nextLink') {
        Get-ScopeTags -Uri $response.'@odata.nextLink'
    }
}

# Get all scope tags and find the ID for the defined name
$scopetagsUri = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags"
$scopeTags = Get-ScopeTags -Uri $scopetagsUri

if (-not $scopeTagId) {
    Write-Error "Scope tag with name '$scopeTagName' not found."
    exit
}

# Step 3: Function to get Managed Devices
function Get-ManagedDevices {
    param($Uri)
    $response = Invoke-MgGraphRequest -Uri $Uri -Method GET
    $response.value

    # Recursively call for next link if available
    if ($response.'@odata.nextLink') {
        Get-ManagedDevices -Uri $response.'@odata.nextLink'
    }
}

# Get all managed devices
$managedDevicesUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"
$managedDevices = Get-ManagedDevices -Uri $managedDevicesUri

# Step 4: Set the scope tag for each managed device
foreach ($device in $managedDevices) {
    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$($device.id)')"
    $body = @{
        roleScopeTagIds = @($scopeTagId)
    } | ConvertTo-Json

    Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $body -ContentType "application/json"
    Write-Host "Set scope tag for device $($device.id)"
}
