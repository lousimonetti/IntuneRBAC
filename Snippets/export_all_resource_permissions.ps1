# Step 1: Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementRBAC.Read.All"

# Step 2: Function to Fetch Permissions
function Get-Profiles {
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
$permissionsUri = "https://graph.microsoft.com/beta/deviceManagement/resourceOperations"
$permissions = Get-Profiles -Uri $permissionsUri

# Step 3: Format, Sort Output, as Gridview
$permissions | Select-Object @{Name='Permissions'; Expression={$_.resourceName + "/" + $_.actionName}},
    @{Name='Description'; Expression={$_.description}} | 
    Sort-Object Permissions | 
    Out-GridView -PassThru -Title "Select Permissions to Export" 

#| Export-Csv -Path "C:\Users\UgurKoc\Downloads\permissions.csv" -NoTypeInformation 