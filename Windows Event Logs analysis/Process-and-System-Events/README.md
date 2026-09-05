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

| Event ID | Name | Log | Tier | SOC Importance |
|----------|------|-----|------|---------------|
| [4688](./Event-4688_New-Process-Created/) | New Process Created | Security | 🔴 Tier 1 | Very High |
| [4689](./Event-4689_Process-Exited/) | Process Exited | Security | 🔴 Tier 1 | Medium (pair with 4688) |
| [4698](./Event-4698_Scheduled-Task-Created/) | Scheduled Task Created | Security | 🟠 Tier 2 | High |
| [4699](./Event-4699_Scheduled-Task-Deleted/) | Scheduled Task Deleted | Security | 🟠 Tier 2 | Medium–High |
| [4700](./Event-4700_Scheduled-Task-Enabled/) | Scheduled Task Enabled | Security | 🟠 Tier 2 | Medium |
| [4701](./Event-4701_Scheduled-Task-Disabled/) | Scheduled Task Disabled | Security | 🟠 Tier 2 | Medium |
| [4702](./Event-4702_Scheduled-Task-Modified/) | Scheduled Task Modified | Security | 🟠 Tier 2 | High |
| [4103](./Event-4103_PowerShell-Module-Logging/) | PowerShell Module Logging | PS/Operational | 🔴 Tier 1 | High |
| [4104](./Event-4104_PowerShell-Script-Block-Logging/) | PowerShell Script Block Logging | PS/Operational | 🔴 Tier 1 | Very High |
| [7045](./Event-7045_New-Service-Installed/) | New Service Installed | System | 🟠 Tier 2 | High |
| [4697](./Event-4697_Service-Installed-Security-Log/) | Service Installed (Security Log) | Security | 🟠 Tier 2 | High |
| [7000](./Event-7000_Service-Failed-To-Start/) | Service Failed to Start | System | 🟠 Tier 2 | Medium–High |
| [7036](./Event-7036_Service-Started-Stopped/) | Service Started or Stopped | System | 🟠 Tier 2 | Medium |
| [7040](./Event-7040_Service-Start-Type-Changed/) | Service Start Type Changed | System | 🟠 Tier 2 | High |

---

## Audit Policies Required

Before working with any event in this category, run these setup commands as Administrator:

```powershell
# Process Creation and Termination (for 4688, 4689)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable

# Command Line Logging in Process Events (critical for 4688 usefulness)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Scheduled Task Events (for 4698-4702)
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

# Service Installation Security Log (for 4697)
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

# PowerShell Script Block Logging (for 4104)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# PowerShell Module Logging (for 4103)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*"

gpupdate /force
```

---

## Lab Environment

- **Domain:** TECHCORP / techcorp.local
- **Server:** WIN-KAHJ94DKN9V
- **Platform:** Windows Server (VirtualBox)
- **Test Accounts:** Administrator, alexrivera, scott

---

## Attack Chains This Category Detects

| Attack Technique | Events Involved |
|-----------------|----------------|
| Malware execution | 4688 → 4689 |
| Obfuscated PowerShell attack | 4688 → 4104 |
| Persistence via scheduled task | 4688 → 4698 → 4702 |
| Attacker cleanup after attack | 4698 → 4688 → 4699 |
| Task hijacking (modify existing task) | 4702 → 4688 |
| PowerShell recon and lateral movement | 4103 → 4104 |
| Security task disabled to reduce visibility | 4701 |
| Malware installs itself as a service | 7045 + 4697 |
| Malware service fails (AV killed binary) | 7045 → 7000 |
| Attacker sets service to auto-start | 7045 → 7040 |
| Attacker disables security service permanently | 7040 (disabled) |
| Security tool stopped to reduce visibility | 7036 (stopped) |
| Full service persistence chain | 7045 → 7040 → 7036 → 4688 |

---

## Priority Reference for SOC

When triaging alerts in this category, focus in this order:

1. **4688** – New Process Created (command line + parent process chain)
2. **4104** – PowerShell Script Block (full script content — highest value)
3. **7045 + 4697** – New Service Installed (always check both logs)
4. **4698** – Scheduled Task Created (persistence)
5. **7040** – Service Start Type Changed (persistence or defense evasion)
6. **4702** – Scheduled Task Modified (task hijacking)
7. **4103** – PowerShell Module Logging (cmdlet tracking)
8. **7036** – Service Started/Stopped (security tools being killed)
9. **4699** – Scheduled Task Deleted (attacker cleanup)
10. **7000** – Service Failed to Start (correlate with 7045)
11. **4689** – Process Exited (pair with 4688 for timeline)
12. **4700/4701** – Task Enabled/Disabled (evasion and security tool tampering)
