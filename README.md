# IntuneRBAC

A comprehensive PowerShell-based tool for managing and auditing Role-Based Access Control (RBAC) in Microsoft Intune. This tool provides detailed insights into your Intune RBAC configuration, including role assignments, scope tags, and permissions.

## Features

- **RBAC Health Check**: Comprehensive analysis of your Intune RBAC configuration
- **Role Management**: Export and analyze role definitions and assignments
- **Scope Tag Management**: Export and manage scope tags across devices, policies, and applications
- **Permission Analysis**: Detailed breakdown of role permissions and assignments
- **Resource Management**: Export and manage resource permissions across your Intune environment

## Prerequisites

- PowerShell 7 or higher
- Microsoft.Graph PowerShell module
- Appropriate Microsoft Graph API permissions:
  - DeviceManagementRBAC.Read.All
  - DeviceManagementApps.Read.All
  - DeviceManagementConfiguration.Read.All
  - User.ReadBasic.All

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

### RBAC Health Check

The main script (`RBAC_HealthCheck.ps1`) provides:

- Role distribution analysis (built-in vs. custom roles)
- Scope tag coverage analysis
- Role assignment overview
- Permission tiering analysis
- Resource permission mapping

### Scope Tag Management

- Export all scope tags across different resource types
- Assign scope tags to devices and applications
- Analyze scope tag coverage and gaps

### Role Management

- Export role definitions and assignments
- Analyze role permissions
- Track role usage and assignments

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the terms specified in the LICENSE file.

## Support

For issues and feature requests, please use the GitHub Issues section of this repository.
