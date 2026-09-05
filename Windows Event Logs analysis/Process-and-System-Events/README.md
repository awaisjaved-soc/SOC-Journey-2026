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
|----------|------|-----|---------------|
| [4688](./Event-4688_New-Process-Created/) | New Process Created | Security | Very High |
| [4689](./Event-4689_Process-Exited/) | Process Exited | Security | Medium (pair with 4688) |
| [4103](./Event-4103_PowerShell-Module-Logging/) | PowerShell Module Logging | PS/Operational | High |
| [4104](./Event-4104_PowerShell-Script-Block-Logging/) | PowerShell Script Block Logging | PS/Operational | Very High |

---

### 🟠 Tier 2 — Scheduled Task & Service Events

| Event ID | Name | Log | SOC Importance |
|----------|------|-----|---------------|
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
|----------|------|-----|---------------|
| [4656](./Event-4656_Handle-Requested/) | A Handle to an Object Was Requested | Security | High |
| [4657](./Event-4657_Registry-Value-Modified/) | A Registry Value Was Modified | Security | Very High |
| [4660](./Event-4660_Object-Deleted/) | An Object Was Deleted | Security | High |
| [4663](./Event-4663_Object-Access-Attempt/) | An Attempt Was Made to Access an Object | Security | High |
| [4616](./Event-4616_System-Time-Changed/) | The System Time Was Changed | Security | High |

---

### 🔵 Tier 3 — System Lifecycle Events

| Event ID | Name | Log | SOC Importance |
|----------|------|-----|---------------|
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

### For Scheduled Task & Service Events (4698–4702, 7045, 4697, 7000, 7036, 7040)

```powershell
# Scheduled Task Events
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

# Service Installation in Security Log (4697)
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
```

### For Object Access & Integrity Events (4656, 4657, 4660, 4663, 4616)

```powershell
# Registry and File auditing
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable

# System time change auditing
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
```

> **Note for 4656, 4657, 4660, 4663:** Audit policy alone is not enough. You must also configure a SACL (Security Access Control List) on each specific registry key or file you want to audit. See each event's individual README for SACL setup steps.

### For System Lifecycle Events (4608, 4609, 6005, 6006, 6008)

```powershell
# Security State Change — covers 4608 and 4609
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
```

> **Note for 6005, 6006, 6008:** No audit policy required. These events are written automatically by the Windows Event Log service itself during boot and shutdown cycles.

### Apply All Policies

```powershell
gpupdate /force
```

### Verify Everything Is Active

```powershell
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
|-----------------|----------------|
| Malware execution | 4688 → 4689 |
| Obfuscated PowerShell attack | 4688 → 4104 |
| Persistence via scheduled task | 4688 → 4698 → 4702 |
| Attacker cleanup after attack | 4698 → 4688 → 4699 |
| Task hijacking (modify existing task) | 4702 → 4688 |
| PowerShell recon and lateral movement | 4103 → 4104 |
| Security task disabled to reduce visibility | 4701 |

### Service-Based Chains

| Attack Technique | Events Involved |
|-----------------|----------------|
| Malware installs itself as a service | 7045 + 4697 |
| Malware service fails (AV killed binary) | 7045 → 7000 |
| Attacker sets service to auto-start | 7045 → 7040 |
| Attacker disables security service permanently | 7040 (disabled) |
| Security tool stopped to reduce visibility | 7036 (stopped) |
| Full service persistence chain | 7045 → 7040 → 7036 → 4688 |

### Object Access & Anti-Forensics Chains

| Attack Technique | Events Involved |
|-----------------|----------------|
| Registry persistence via Run key | 4656 → 4663 → 4657 |
| Full persistence + cleanup chain | 4656 → 4663 → 4657 → 4660 → 4616 |
| Attacker reads startup entries (recon) | 4656 → 4663 |
| Evidence file destroyed | 4660 (correlate Handle ID with 4656) |
| Timestamp manipulation (anti-forensics) | 4616 |
| Registry key deletion after attack | 4660 |

### System Lifecycle Chains

| Attack Technique | Events Involved |
|-----------------|----------------|
| Forced reboot to apply persistence | 4609 → 6006 → 6005 → 4608 |
| Crash or power-kill to evade logging | 6008 (no preceding 6006) |
| Unexplained reboot mid-session | 4608 without prior 4609 |
| Off-hours reboot during attack | 6005 timestamp outside business hours |
| Timeline building for incident response | 4608 + 6005 as boot anchors |

---

## Priority Reference for SOC

When triaging alerts in this category, focus in this order:

### Immediate Investigation (Critical)

1. **4688** — New Process Created (command line + parent process chain)
2. **4104** — PowerShell Script Block (full script content — highest intelligence value)
3. **7045 + 4697** — New Service Installed (always check both logs simultaneously)
4. **4657** — Registry Value Modified (Run key or sensitive path modification)

### High Priority

5. **4698** — Scheduled Task Created (persistence mechanism)
6. **7040** — Service Start Type Changed (persistence or defense evasion)
7. **4702** — Scheduled Task Modified (task hijacking)
8. **4616** — System Time Changed (anti-forensics — investigate process name)
9. **6008** — Unexpected Shutdown (crash, forced kill, or attacker-initiated reboot)
10. **6005** — Event Log Service Started (off-hours reboot detection)

### Medium Priority

11. **4103** — PowerShell Module Logging (cmdlet-level tracking)
12. **4663** — Object Access Attempt (read/write to sensitive registry or file)
13. **4656** — Handle Requested (pre-access to sensitive object)
14. **7036** — Service Started/Stopped (security tools being killed)
15. **4699** — Scheduled Task Deleted (attacker cleanup)
16. **7000** — Service Failed to Start (correlate with 7045)
17. **4660** — Object Deleted (correlate Handle ID with 4656 for object name)

### Timeline & Correlation Support

18. **4608** — Windows Starting Up (boot timestamp anchor)
19. **4609** — Windows Shutting Down (session end marker)
20. **6006** — Event Log Service Stopped (clean shutdown confirmation)
21. **4689** — Process Exited (pair with 4688 for full execution timeline)
22. **4700/4701** — Task Enabled/Disabled (evasion and security tool tampering)

---

## Key Concept — Visible vs Silent Events

Understanding which events produce visible results and which are silent is important for lab work:

**Visible Events** — something happens on screen when triggered:
- 4688/4689 — a process window may open and close
- 4698–4702 — Task Scheduler shows the task
- 7045/4697/7036/7040 — Services console reflects the change
- 6005/6006/6008 — the machine actually reboots or shuts down
- 4616 — the system clock visibly changes in the taskbar

**Silent Events** — nothing appears on screen, evidence is only in the Security log:
- 4656 — handle request fires in the kernel, no visual output
- 4657 — registry modification logged silently; only regedit shows the new value
- 4660 — deletion logged silently; the object disappears but no audit popup appears
- 4663 — access operation logged silently; PowerShell shows command output, not the audit event
- 4608/4609 — fire during boot/shutdown sequences with no dedicated on-screen indicator

---

## Folder Structure

```
Process-System-Events/
│
├── README.md                                        ← This file
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
└── Event-6008_Unexpected-Shutdown/
```
