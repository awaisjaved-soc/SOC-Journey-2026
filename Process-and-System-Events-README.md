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

## Total Events Documented: 24

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

### For Scheduled Task & Service Events

```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
```

### For Object Access & Integrity Events (4656, 4657, 4660, 4663, 4616)

```powershell
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
```

> **Note:** For 4656, 4657, 4660, and 4663 — audit policy alone is not enough. You must also configure a SACL on the specific registry key or file. See each event’s README for detailed steps.

### For System Lifecycle Events (4608, 4609, 6005, 6006, 6008)

```powershell
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
```

> **Note:** Events 6005, 6006, and 6008 are generated automatically by the Event Log service. No extra audit policy is required.

### Apply & Verify

```powershell
gpupdate /force
auditpol /get /category:*
```

---

## Lab Environment

- **Domain:** TECHCORP / techcorp.local
- **Server:** WIN-KAHJ94DKN9V
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
| Attacker cleanup after attack | 4698 → 4688 → 4699 |
| Task hijacking | 4702 → 4688 |
| PowerShell recon / lateral movement | 4103 → 4104 |

### Service-Based Chains

| Attack Technique | Events Involved |
|------------------|-----------------|
| Malware installs as service | 7045 + 4697 |
| Service set to auto-start | 7045 → 7040 |
| Security tool stopped | 7036 |
| Full service persistence | 7045 → 7040 → 7036 → 4688 |

### Object Access & Anti-Forensics Chains

| Attack Technique | Events Involved |
|------------------|-----------------|
| Registry persistence (Run key) | 4656 → 4663 → 4657 |
| Full persistence + cleanup | 4656 → 4663 → 4657 → 4660 → 4616 |
| Evidence deleted | 4660 (correlate with 4656) |
| Timestamp manipulation | 4616 |

### System Lifecycle Chains

| Attack Technique | Events Involved |
|------------------|-----------------|
| Forced reboot | 4609 → 6006 → 6005 → 4608 |
| Crash / power-kill | 6008 (no preceding 6006) |
| Off-hours reboot | 6005 outside business hours |

---

## Priority Reference for SOC

### Immediate Investigation (Critical)
1. **4688** — New Process Created  
2. **4104** — PowerShell Script Block Logging  
3. **7045 + 4697** — New Service Installed  
4. **4657** — Registry Value Modified  

### High Priority
5. **4698** — Scheduled Task Created  
6. **7040** — Service Start Type Changed  
7. **4702** — Scheduled Task Modified  
8. **4616** — System Time Changed  
9. **6008** — Unexpected Shutdown  
10. **6005** — Event Log Service Started  

### Medium Priority
11. 4103, 4663, 4656, 7036, 4699, 7000, 4660  

### Timeline Support
12. 4608, 4609, 6006, 4689, 4700, 4701  

---

## Key Concept — Visible vs Silent Events

**Visible Events** (something happens on screen):
- 4688 / 4689, 4698–4702, 7045 / 4697 / 7036 / 7040, 6005 / 6006 / 6008, 4616

**Silent Events** (only visible in Event Viewer):
- 4656, 4657, 4660, 4663, 4608, 4609

---

## Folder Structure

```
Process-and-System-Events/
├── README.md
├── Event-4688_New-Process-Created/
├── Event-4689_Process-Exited/
├── Event-4103_PowerShell-Module-Logging/
├── Event-4104_PowerShell-Script-Block-Logging/
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
├── Event-4656_Handle-Requested/
├── Event-4657_Registry-Value-Modified/
├── Event-4660_Object-Deleted/
├── Event-4663_Object-Access-Attempt/
├── Event-4616_System-Time-Changed/
├── Event-4608_Windows-Starting-Up/
├── Event-4609_Windows-Shutting-Down/
├── Event-6005_Event-Log-Service-Started/
├── Event-6006_Event-Log-Service-Stopped/
└── Event-6008_Unexpected-Shutdown/
```

---

**Part of:** [SOC-Journey-2026](https://github.com/awaisjaved-soc/SOC-Journey-2026)  
**Author:** Muhammad Awais Javed
```
