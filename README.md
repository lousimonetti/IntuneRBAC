# 🔐 Intune role-based access control (RBAC)

A comprehensive PowerShell-based tool for managing and auditing Role-Based Access Control (RBAC) in Microsoft Intune. This tool provides detailed insights into your Intune RBAC configuration, including role assignments, scope tags, and permissions.

![grafik](https://github.com/user-attachments/assets/556309aa-9aec-4982-aca2-b5515e08cd39)

## Features

- **RBAC Health Check**: Generates an interactive HTML report analyzing your Intune RBAC configuration, including:
  - Overall statistics (Total Roles, Custom Roles, Scope Tags).
  - Security analysis (Unused Roles, Overlapping Permissions).
  - Detailed role information (Assignments, Members, Scope Tags, Permissions).
  - A comprehensive Permissions Matrix (Roles vs. Permissions).
  - An interactive Role Relationship Diagram (Roles -> Groups -> Users).
  - **NEW: Security Review Dashboard** (v0.5.0) - Comprehensive risk assessment and security scoring.
- **Snippet Scripts**: Utility scripts for specific tasks like exporting roles, scope tags, assignments, and permissions (see `Snippets/` directory).

## Prerequisites

- PowerShell 7 or higher
- Microsoft.Graph PowerShell module
- Appropriate Microsoft Graph API permissions:
  - `DeviceManagementRBAC.Read.All`: Allows reading of Intune role definitions, assignments, and scope tags.
  - `DeviceManagementApps.Read.All`: Allows reading of application configurations (used for analyzing scope tags on apps).
  - `DeviceManagementConfiguration.Read.All`: Allows reading of device configuration and policy settings (used for analyzing scope tags on policies).
  - `User.ReadBasic.All`: Allows reading basic user profiles (needed to get member details for assigned groups).
  - `Group.Read.All`: Allows reading group memberships (needed for Security Review user counting).

## Installation

### PowerShell Gallery (Recommended)

The script is available on the [PowerShell Gallery](https://www.powershellgallery.com/packages/IntuneRBAC/). You can install it directly using:

```powershell
Install-Script -Name IntuneRBAC
```

### Manual Installation

Alternatively, you can clone this repository or download the script files directly:

```powershell
git clone https://github.com/ugurkocde/IntuneRBAC.git
```

## Usage

### Main Health Check Script

Run the main RBAC health check script to get a comprehensive overview of your Intune RBAC configuration:

```powershell
# If installed from PowerShell Gallery
IntuneRBAC

# If using local script
.\IntuneRBAC.ps1
```

### Additional Scripts

The `Snippets` directory contains various utility scripts for specific RBAC management tasks:

- `export_rbac_roles.ps1`: Export all RBAC roles
- `export_scope_and_roles.ps1`: Export scope tags and their associated roles
- `export_scope_tags.ps1`: Export all scope tags
- `export_rbac_roles_assignments.ps1`: Export role assignments
- `export_rbac_roles_permissions.ps1`: Export role permissions
- `assign_device_scope_tag.ps1`: Assign scope tags to devices
- `assign_apps_scope_tags.ps1`: Assign scope tags to applications

## Features in Detail

### RBAC Health Check (`IntuneRBAC.ps1`)

The main script generates an HTML report featuring:

- **Dashboard**: Key statistics on total roles, custom roles, and scope tags.
- **Security Analysis**: Highlights potential issues like unused roles and roles with overlapping permissions.
- **Roles Overview**: An accordion view for each role detailing:
  - Basic Information (Description, Type, Scope Tags).
  - Assignments (Groups, Members).
  - Security findings (e.g., Unused, Overlaps).
  - Risk Score Badge (NEW in v0.5.0).
  - Allowed Resource Actions (categorized and searchable).
- **Permissions Matrix**: A table showing which roles have which specific permissions.
- **Relationship Diagram**: An interactive graph visualizing the connections between Roles, assigned Groups, and group Members (Users).

### Security Review Dashboard (NEW in v0.5.0)

The Security Review feature provides a comprehensive risk assessment of your RBAC configuration:

#### Overall Health Score
- **Score Range**: 0-100 points (higher is better)
- **Letter Grades**: A (90-100), B (80-89), C (70-79), D (60-69), F (0-59)
- **Score Breakdown**: Shows exactly which issues are impacting your score

#### Risk Scoring Methodology

Each role receives a risk score (0-100) based on four factors:

1. **Permission Criticality (0-40 points)**
   - Evaluates the potential impact of granted permissions
   - Critical operations (wipe, delete): 40 points per permission
   - High-impact operations: 30-35 points
   - Modification operations: 20-25 points
   - Read operations: 5-10 points

2. **Scope Exposure (0-20 points)**
   - No scope tags (org-wide): 20 points
   - Multiple scope tags: 15 points
   - Single scope tag: 10 points

3. **User Exposure (0-20 points)**
   - >50 users: 20 points
   - 20-50 users: 15 points
   - 5-20 users: 10 points
   - 1-5 users: 5 points

4. **Configuration Risk (0-20 points)**
   - Custom role with >20 permissions: +10 points
   - >5 critical permissions: +10 points

**Risk Levels**: Critical (80-100), High (60-79), Medium (40-59), Low (0-39)

#### Health Score Deductions
- **Critical Risk Roles**: -15 points each
- **High Risk Roles**: -8 points each
- **Medium Risk Roles**: -3 points each
- **Unused Roles**: -3 points each (max -15 total)
- **Excessive Permissions** (>50): -5 points each

### Customizing Risk Scores

You can adjust the risk scoring to match your organization's risk tolerance:

1. **Edit Permission Risk Values** in `Get-CriticalPermissions` function:
   ```powershell
   # Example: Make device wipe less critical
   "Devices_Wipe" = 30  # Changed from 40
   ```

2. **Adjust User Count Thresholds** in `Calculate-RoleRiskScore`:
   ```powershell
   # Example: For smaller organizations
   if ($userCount -gt 20) { $userScore = 20 }     # Changed from 50
   elseif ($userCount -gt 10) { $userScore = 15 }  # Changed from 20
   ```

3. **Modify Health Score Deductions** in `Calculate-OverallHealthScore`:
   ```powershell
   # Example: Make critical roles more impactful
   $deductions['CriticalRoles'] = $criticalRoles * 20  # Changed from 15
   ```

### Interpreting Security Review Results

#### Health Score Grades
- **A (90-100)**: Excellent security posture, minimal risks
- **B (80-89)**: Good security with some areas for improvement
- **C (70-79)**: Moderate security, several issues need attention
- **D (60-69)**: Poor security posture, significant improvements needed
- **F (0-59)**: Critical security issues requiring immediate action

#### Common Issues and Remediation
1. **High Risk Scores**
   - Review roles with Critical/High risk ratings
   - Consider splitting roles with too many permissions
   - Implement scope tags to limit access breadth

2. **Unused Roles**
   - Remove roles with no assignments
   - Archive or document if needed for compliance

3. **Excessive Permissions**
   - Apply principle of least privilege
   - Create focused roles for specific tasks
   - Regular permission audits

### Snippet Scripts (`Snippets/` directory)

Contains various utility scripts for specific RBAC management tasks, such as:

- Exporting roles, scope tags, assignments, permissions.
- Assigning scope tags to devices or applications.
  _(Refer to the script names in the directory for specific functions)_

_(Role/Scope Tag management details are covered by the Snippet Scripts)_

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the terms specified in the LICENSE file.

## Support

For issues and feature requests, please use the GitHub Issues section of this repository.
