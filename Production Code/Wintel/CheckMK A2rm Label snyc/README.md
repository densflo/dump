# CheckMK A2RM Label Sync

Overview
This project consists of PowerShell scripts designed to synchronize application and service tier information from an A2RM API with host labels in a CheckMK monitoring system.

Scripts

1.  CheckMK.psm1

    Purpose
    This module provides a collection of functions for interacting with the CheckMK API. It includes functions for establishing connections, retrieving host information, creating and modifying hosts, managing downtimes, and more.

    Functions:

    *   Get-CMKConnection

        Purpose
        Establishes a connection to the CheckMK API.

        Function Signature
        ```powershell
        Get-CMKConnection -Hostname "cmk-prod.corp.ad.tullib.com" -Sitename "Main" -Username 'Wintel' -Secret (ConvertTo-SecureString "Kintaro1212!" -AsPlainText -Force)
        ```

        Parameters
        *   Hostname (Mandatory): DNS-Name des CheckMK-Servers
        *   Sitename (Mandatory): Instanz auf dem CheckMK-Server
        *   Username (Optional): Benutzer mit genügend Rechten in CheckMK. Per Standard wird der Skriptausführende Benutzer gewählt.
        *   Secret (Mandatory): Passwort zum Zugriff auf die CheckMK API.
        *   IfMatch (Optional): Wenn bestehende Objekte bearbeitet werden sollen, muss das ETag des Objektes zuvor abgerufen und bei der Änderungsanfrage in den Header eingefügt werden.

    *   Get-CMKHost

        Purpose
        Retrieves host information from CheckMK.

        Function Signature
        ```powershell
        Get-CMKHost -HostName "hostname" -Connection $Connection
        ```

        Parameters
        *   HostName (Mandatory): The name of the host.
        *   Connection (Mandatory): The connection object obtained from Get-CMKConnection.

    *   New-CMKHost

        Purpose
        Creates a new host in CheckMK.

        Function Signature
        ```powershell
        New-CMKHost -HostName "hostname" -FolderPath "~folder" -Connection $Connection
        ```

        Parameters
        *   HostName (Mandatory): The name of the host.
        *   FolderPath (Mandatory): The path to the folder. Use tilde (~) instead of slash.
        *   Connection (Mandatory): The connection object obtained from Get-CMKConnection.

    *   Remove-CMKHost

        Purpose
        Removes a host from CheckMK.

        Function Signature
        ```powershell
        Remove-CMKHost -HostName "hostname" -Connection $Connection
        ```

        Parameters
        *   HostName (Mandatory): The name of the host.
        *   Connection (Mandatory): The connection object obtained from Get-CMKConnection.

    Dependencies
    *   PowerShell
    *   CheckMK API

2.  Get-a2rmapp.ps1

    Purpose
    This script defines a function, `get-appa2rm`, that retrieves application instance data from the A2RM API for a given computer name. It extracts information such as application name, APM status, environment, region, and owner details.

    Function Signature
    ```powershell
    get-appa2rm -ComputerName $env:computername
    ```

    Dependencies
    *   PowerShell
    *   curl.exe
    *   A2RM API

3.  get-cmklist.ps1

    Purpose
    This script defines a function, `get-cmklist`, that retrieves a list of hostnames from the CheckMK API. It filters out hostnames that match specific patterns (e.g., `^pod_`, `_q08_`, `_p10_`, `_p09_`).

    Function Signature
    ```powershell
    get-cmklist
    ```

    Dependencies
    *   PowerShell
    *   curl.exe
    *   CheckMK API

4.  Main\_updater.ps1

    Purpose
    This is the main script that orchestrates the synchronization process. It retrieves hostnames from CheckMK, fetches application data from A2RM, and updates the host labels in CheckMK with the application and service tier information.

    Flow
    1.  Imports Modules: Imports the necessary modules, including `CheckMK.psm1`, `Get-a2rmapp.ps1`, and `get-cmklist.ps1`.
    2.  Configuration: Defines configuration parameters such as batch size, retry attempts, and memory check interval.
    3.  Logging: Sets up a log file to record script execution details.
    4.  Connection Setup: Establishes a connection to the CheckMK API using the `Get-CMKConnection` function from the `CheckMK.psm1` module.
    5.  Host Processing:
        *   Retrieves a list of hostnames from CheckMK using the `get-cmklist` function.
        *   Processes hosts in batches to manage memory usage.
        *   For each host:
            *   Retrieves host information from CheckMK using the `Get-CMKHost` function.
            *   Retrieves application data from A2RM using the `get-appa2rm` function.
            *   Clears existing application tier labels from the host.
            *   Adds new labels based on the application and service tier information retrieved from A2RM.
    6.  Change Activation: Activates the changes in CheckMK to apply the updated host labels.

    Dependencies
    *   PowerShell
    *   CheckMK.psm1
    *   Get-a2rmapp.ps1
    *   get-cmklist.ps1
    *   CheckMK API
    *   A2RM API

Security and Credential Management
The scripts use API credentials for accessing CheckMK and A2RM. Ensure that these credentials are stored securely and are not exposed in the script code.

Limitations
*   Requires network connectivity to target servers.
*   Depends on external APIs (CheckMK and A2RM).
*   Requires appropriate user permissions for remote information gathering.

Recommended Permissions
*   Domain User with Read access to Active Directory (if applicable).
*   Local Administrator or equivalent permissions on target servers (if applicable).

Mermaid Diagram
```mermaid
graph LR
    A[Start Main_updater.ps1] --> B{Get CMK Host List};
    B --> C{Process Hosts in Batches};
    C --> D{Get CMK Host Data};
    D --> E{Get A2RM App Data};
    E --> F{Clear Existing Labels};
    F --> G{Add New Labels};
    G --> H{Get CMK Pending Changes};
    H --> I{Invoke CMK Change Activation};
    I --> J[End];
