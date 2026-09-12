
# Process & System Events – SOC Journey 2026

Windows Security Event logs for the **Process & System Events** category, documented as part of the SOC Analyst learning path.

Each folder contains a dedicated README with:
- Event explanation and SOC importance
- Setup / audit policy requirements
- How to generate the event (GUI + PowerShell methods)
- Troubleshooting for common lab issues
- Detection commands (PowerShell)
- SOC analyst notes and red flags

---

## Events Covered

### 🔴 Tier 1 — Process & PowerShell Events

| Event ID | Name | Log | SOC Importance |
|----------|------|-----|----------------|
| [4688](./Event-4688_New-Process-Created/) | New Process Created | Security | Very High |
| [4689](./Event-4689_Process-Exited/) | Process Exited | Security | Medium (pair with 4688) |
| [4103](./Event-4103_PowerShell-Module-Logging/) | PowerShell Module Logging | PS/Operational | High |
| [4104](./Event-4104_PowerShell-Script-Block-Logging/) | PowerShell Script Block Logging | PS/Operational | Very High |

---

### 🟠 Tier 2 — Scheduled Task & Service Events

| Event ID | Name | Log | SOC Importance |
|----------|------|-----|----------------|
| [4698](./Event-4698_Scheduled-Task-Created/) | Scheduled Task Created | Security | High |
| [4699](./Event-4699_Scheduled-Task-Deleted/) | Scheduled Task Deleted | Security | Medium–High |
| [4700](./Event-4700_Scheduled-Task-Enabled/) | Scheduled Task Enabled | Security | Medium |
| [4701](./Event-4701_Scheduled-Task-Disabled/) | Scheduled Task Disabled | Security | Medium |
| [4702](./Event-4702_Scheduled-Task-Modified/) | Scheduled Task Modified | Security | High |
| [7045](./Event-7045_New-Service-Installed/) | New Service Installed | System | High |
| [4697](./Event-4697_Service-Installed-Security-Log/) | Service Installed (Security Log) | Security | High |
| [7000](./Event-7000_Service-Failed-To-Start/) | Service Failed to Start | System | Medium–High |
| [7036](./Event-7036_Service-Started-Stopped/) | Service Started or Stopped | System | Medium |
| [7040](./Event-7040_Service-Start-Type-Changed/) | Service Start Type Changed | System | High |

---

### 🟡 Tier 3 — Object Access & System Integrity Events

| Event ID | Name | Log | SOC Importance |
|----------|------|-----|----------------|
| [4656](./Event-4656_Handle-Requested/) | A Handle to an Object Was Requested | Security | High |
| [4657](./Event-4657_Registry-Value-Modified/) | A Registry Value Was Modified | Security | Very High |
| [4660](./Event-4660_Object-Deleted/) | An Object Was Deleted | Security | High |
| [4663](./Event-4663_Object-Access-Attempt/) | An Attempt Was Made to Access an Object | Security | High |
| [4616](./Event-4616_System-Time-Changed/) | The System Time Was Changed | Security | High |

---

### 🔵 Tier 3 — System Lifecycle Events

| Event ID | Name | Log | SOC Importance |
|----------|------|-----|----------------|
| [4608](./Event-4608_Windows-Starting-Up/) | Windows Is Starting Up | Security | Medium — boot anchor |
| [4609](./Event-4609_Windows-Shutting-Down/) | Windows Is Shutting Down | Security | Medium — session end marker |
| [6005](./Event-6005_Event-Log-Service-Started/) | Event Log Service Started (System Reboot) | System | High — reboot detection |
| [6006](./Event-6006_Event-Log-Service-Stopped/) | Event Log Service Stopped (Clean Shutdown) | System | Medium — clean shutdown |
| [6008](./Event-6008_Unexpected-Shutdown/) | Previous Unexpected Shutdown | System | High — crash or forced kill |

---

### 🟣 Tier 4 — WMI Activity & Persistence Events

| Event ID | Name | Log | SOC Importance |
|----------|------|-----|----------------|
| [5857](./Event-5857_WMI-Activity-Detected/) | WMI Activity Detected | WMI-Activity/Operational | Medium–High |
| [5858](./Event-5858_WMI-Query-Error/) | WMI Query Error | WMI-Activity/Operational | Medium |
| [5860](./Event-5860_Temporary-WMI-Subscription/) | Temporary WMI Subscription Created | WMI-Activity/Operational | High |
| [5861](./Event-5861_Permanent-WMI-Subscription/) | Permanent WMI Subscription Created | WMI-Activity/Operational | Very High |
| [5861 Lab](./Event-5861_WMI-Permanent-Subscription-Persistence-Lab/) | WMI Permanent Subscription Persistence Lab | WMI-Activity/Operational | Critical (Full Lab) |

---

## Total Events Documented: 29

---

## Audit Policies Required

### For Process & PowerShell Events (4688, 4689, 4103, 4104)

```powershell
# Process Creation and Termination
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable

# Command Line Logging — critical for 4688 to show full command
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# PowerShell Script Block Logging (4104)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# PowerShell Module Logging (4103)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*"
```

### For Scheduled Task & Service Events (4698–4702, 7045, 4697, 7000, 7036, 7040)

```powershell
# Scheduled Task Events
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

# Service Installation in Security Log (4697)
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
```

### For Object Access & Integrity Events (4656, 4657, 4660, 4663, 4616)

```powershell
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
```

> **Note:** For 4656, 4657, 4660, 4663 you must also configure a SACL on the specific registry key or file.

### For System Lifecycle Events (4608, 4609, 6005, 6006, 6008)

```powershell
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
```

### For WMI Events (5857, 5858, 5860, 5861)

No special `auditpol` command is required.  
These events are written automatically to the **Microsoft-Windows-WMI-Activity/Operational** log.

```powershell
gpupdate /force
```

---

## Lab Environment

- **Domain:** TECHCORP / techcorp.local
- **Platform:** Windows Server (VirtualBox)
- **Test Accounts:** Administrator, alexrivera, scott

---

## Attack Chains This Category Detects

### Process & Execution Chains

| Attack Technique | Events Involved |
|------------------|-----------------|
| Malware execution | 4688 → 4689 |
| Obfuscated PowerShell attack | 4688 → 4104 |
| Persistence via scheduled task | 4688 → 4698 → 4702 |
| Task hijacking | 4702 → 4688 |

### Service-Based Chains

| Attack Technique | Events Involved |
|------------------|-----------------|
| Malware installs as a service | 7045 + 4697 |
| Service set to auto-start | 7045 → 7040 |
| Security tool stopped | 7036 |

### Object Access & Anti-Forensics

| Attack Technique | Events Involved |
|------------------|-----------------|
| Registry Run key persistence | 4656 → 4663 → 4657 |
| Timestamp manipulation | 4616 |

### WMI Persistence Chains

| Attack Technique | Events Involved |
|------------------|-----------------|
| Temporary WMI subscription | 5860 |
| Permanent WMI persistence | 5861 |
| Full WMI attack + execution | 5857 → 5861 → 4688 |

---

## Priority Reference for SOC

**Critical**
1. **4688** – New Process Created
2. **4104** – PowerShell Script Block
3. **5861** – Permanent WMI Subscription
4. **7045 + 4697** – New Service Installed
5. **4657** – Registry Value Modified

**High Priority**
6. **4698** – Scheduled Task Created
7. **7040** – Service Start Type Changed
8. **4702** – Scheduled Task Modified
9. **4616** – System Time Changed
10. **6008** – Unexpected Shutdown

---

## Folder Structure

```
Process-System-Events/
│
├── README.md
│
├── Event-4688_New-Process-Created/
├── Event-4689_Process-Exited/
├── Event-4103_PowerShell-Module-Logging/
├── Event-4104_PowerShell-Script-Block-Logging/
│
├── Event-4698_Scheduled-Task-Created/
├── Event-4699_Scheduled-Task-Deleted/
├── Event-4700_Scheduled-Task-Enabled/
├── Event-4701_Scheduled-Task-Disabled/
├── Event-4702_Scheduled-Task-Modified/
├── Event-7045_New-Service-Installed/
├── Event-4697_Service-Installed-Security-Log/
├── Event-7000_Service-Failed-To-Start/
├── Event-7036_Service-Started-Stopped/
├── Event-7040_Service-Start-Type-Changed/
│
├── Event-4656_Handle-Requested/
├── Event-4657_Registry-Value-Modified/
├── Event-4660_Object-Deleted/
├── Event-4663_Object-Access-Attempt/
├── Event-4616_System-Time-Changed/
│
├── Event-4608_Windows-Starting-Up/
├── Event-4609_Windows-Shutting-Down/
├── Event-6005_Event-Log-Service-Started/
├── Event-6006_Event-Log-Service-Stopped/
├── Event-6008_Unexpected-Shutdown/
│
├── Event-5857_WMI-Activity-Detected/
├── Event-5858_WMI-Query-Error/
├── Event-5860_Temporary-WMI-Subscription/
├── Event-5861_Permanent-WMI-Subscription/
└── Event-5861_WMI-Permanent-Subscription-Persistence-Lab/
```
```


