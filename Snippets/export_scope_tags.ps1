# Step 1: Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementRBAC.Read.All"

# Step 2: Function to Fetch Permissions
function Get-ScopeTags {
    param($Uri)
    $response = Invoke-MgGraphRequest -Uri $Uri -Method GET

    # Return the response values
    $response.value

    # Recursively call for next link if available
    if ($response.'@odata.nextLink') {
        Get-Profiles -Uri $response.'@odata.nextLink'
    }
}

# Fetch Permissions
$scopetagsUri = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags"
Get-ScopeTags -Uri $scopetagsUri


Out-GridView -PassThru -Title "Select Permissions to Export" 
#| Export-Csv -Path "C:\Users\UgurKoc\Downloads\permissions.csv" -NoTypeInformation 


