# 🔐 Intune role-based access control (RBAC)

A comprehensive PowerShell-based tool for managing and auditing Role-Based Access Control (RBAC) in Microsoft Intune. This tool provides detailed insights into your Intune RBAC configuration, including role assignments, scope tags, and permissions.

> **Note**: The RBAC Health Check Script is currently in preview.

## Features

- **RBAC Health Check**: Generates an interactive HTML report analyzing your Intune RBAC configuration, including:
  - Overall statistics (Total Roles, Custom Roles, Scope Tags).
  - Security analysis (Unused Roles, Overlapping Permissions).
  - Detailed role information (Assignments, Members, Scope Tags, Permissions).
  - A comprehensive Permissions Matrix (Roles vs. Permissions).
  - An interactive Role Relationship Diagram (Roles -> Groups -> Users).
- **Snippet Scripts**: Utility scripts for specific tasks like exporting roles, scope tags, assignments, and permissions (see `Snippets/` directory).

## Prerequisites

- PowerShell 7 or higher
- Microsoft.Graph PowerShell module
- Appropriate Microsoft Graph API permissions:
  - `DeviceManagementRBAC.Read.All`: Allows reading of Intune role definitions, assignments, and scope tags.
  - `DeviceManagementApps.Read.All`: Allows reading of application configurations (used for analyzing scope tags on apps).
  - `DeviceManagementConfiguration.Read.All`: Allows reading of device configuration and policy settings (used for analyzing scope tags on policies).
  - `User.ReadBasic.All`: Allows reading basic user profiles (needed to get member details for assigned groups).

## Usage

### Main Health Check Script

Run the main RBAC health check script to get a comprehensive overview of your Intune RBAC configuration:

```powershell
.\RBAC_HealthCheck.ps1
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

### RBAC Health Check (`RBAC_HealthCheck.ps1`)

The main script generates an HTML report featuring:

- **Dashboard**: Key statistics on total roles, custom roles, and scope tags.
- **Security Analysis**: Highlights potential issues like unused roles and roles with overlapping permissions.
- **Roles Overview**: An accordion view for each role detailing:
  - Basic Information (Description, Type, Scope Tags).
  - Assignments (Groups, Members).
  - Security findings (e.g., Unused, Overlaps).
  - Allowed Resource Actions (categorized and searchable).
- **Permissions Matrix**: A table showing which roles have which specific permissions.
- **Relationship Diagram**: An interactive graph visualizing the connections between Roles, assigned Groups, and group Members (Users).

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
