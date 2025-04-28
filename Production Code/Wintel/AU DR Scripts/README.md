# AU DR Scripts

## Description

This repository contains a collection of scripts used to automate the Disaster Recovery (DR) process for Wintel in Australia. These scripts facilitate environment switching, status checking, and server operations to enhance operational efficiency during DR exercises.

## Scripts Included and Their Purposes

### Wintel Management Scripts
- `Poweron_au_servers.ps1`: 
  - Purpose: Automates the power-on process for Australian servers in the DR environment
  - Functionality: 
    * Connects to VMware vCenter
    * Authenticates user credentials
    * Starts servers listed in a predefined notepad list
    * Provides logging and status updates

- `Shutdown_au_servers.ps1`:
  - Purpose: Safely powers down Australian servers during DR preparation
  - Functionality:
    * Connects to VMware vCenter
    * Authenticates user credentials
    * Gracefully shuts down servers listed in a predefined notepad list
    * Ensures proper server state preservation

- `Au_server_status.ps1`:
  - Purpose: Checks and reports the current status of Australian servers
  - Functionality:
    * Retrieves server power state
    * Checks connectivity
    * Generates a comprehensive status report

### DNS and Environment Switching Scripts

#### ETC Database Scripts
- `ETC_DB_check.ps1`:
  - Purpose: Verifies DNS configurations for ETC database servers
  - Functionality:
    * Checks current DNS mappings
    * Validates connectivity to database endpoints
    * Reports any discrepancies

- `ETC_DB_DNS_Switch.ps1`:
  - Purpose: Switches DNS entries between production and DR environments for ETC databases
  - Functionality:
    * Modifies DNS configurations
    * Supports switching between PROD and DR environments
    * Provides rollback capabilities

#### GUIBIOS Scripts
- `GUIBIOS_DNS_check.ps1`:
  - Purpose: Validates DNS configurations for GUIBIOS application environment
  - Functionality:
    * Checks current DNS mappings
    * Verifies endpoint connectivity
    * Generates detailed DNS status report

- `GUIBIOS_DNS_switch.ps1`:
  - Purpose: Switches DNS configurations for GUIBIOS main environment
  - Functionality:
    * Modifies DNS entries
    * Supports switching between PROD and DR environments

- `GUIBOS_APP_DNS_CHECK.ps1`:
  - Purpose: Checks DNS configurations specifically for GUIBIOS application servers
  - Functionality:
    * Validates application-specific DNS entries
    * Reports any configuration issues

- `GUIBOS_APP_DNS_SWITCH.ps1`:
  - Purpose: Switches DNS for GUIBIOS application servers
  - Functionality:
    * Modifies application server DNS configurations
    * Supports environment switching

- `GUIBOS_DB_DNS_CHECK.ps1`:
  - Purpose: Validates DNS configurations for GUIBIOS database servers
  - Functionality:
    * Checks database-specific DNS entries
    * Ensures proper database endpoint routing

- `GUIBOS_DB_DNS_SWITCH.ps1`:
  - Purpose: Switches DNS configurations for GUIBIOS database servers
  - Functionality:
    * Modifies database server DNS entries
    * Supports switching between environments

#### TMS Scripts
- `TMS_DNS_CHECK.ps1`:
  - Purpose: Checks DNS configurations for TMS (Transaction Management System)
  - Functionality:
    * Validates TMS-specific DNS entries
    * Reports connectivity and routing status

- `TMS_DNS_switch.ps1`:
  - Purpose: Switches DNS configurations for TMS environment
  - Functionality:
    * Modifies TMS DNS entries
    * Supports switching between PROD and DR environments

## Installation

Clone the repository to your local machine using the following command:

```bash
git clone "https://scm.tpicapcloud.com/wintel-team/au_dr_scripts.git"
```

## Usage
Scripts containing the word "SWITCH" in their filenames can be activated using the -switch parameter:

- `-switch PROD` sets DNS entries for the production environment
- `-switch DR` sets DNS entries for the DR environment
- Scripts containing "CHECK" in their filenames are used to verify DNS entries for endpoints

For VMware scripts, run `Shutdown_au_servers` and `Poweron_au_servers`. These scripts will:
- Prompt for vCenter authentication
- Open a notepad process listing servers to be managed

## Examples
To run a script in PowerShell:

```PowerShell
.\ETC_DB_check.ps1
. .\ETC_DB_DNS_Switch.ps1
ETC_DB_DNS_Switch.ps1 -switch DR  # Switch the environment to DR
ETC_DB_DNS_Switch.ps1 -switch PROD  # Switch the environment to production
ETC_DB_DNS_Check.ps1  # Check the DNS entries
```

## Support
For issues with the scripts, please contact:
- Dennis Jeffrey Flores: dennisjeffrey.flores@tpicap.com
- TP ICAP Global Wintel Administrators: WintelAdministrators@tpicap.com

## Roadmap
Future plans involve:
- Integrating scripts into AWX for automated execution
- Enhancing output consistency
- Improving user-friendliness

## Contributing
Contributions are welcome. Please contact dennisjeffrey.flores@tpicap.com to discuss improvements or submit a pull request for review.
