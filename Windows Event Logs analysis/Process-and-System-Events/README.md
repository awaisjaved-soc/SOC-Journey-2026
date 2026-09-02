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
| [4104](./Event-4104_PowerShell-Script-Block-Logging/) | PowerShell Script Block Logging | PS/Operational | 🔴 Tier 1 | Very High |
| [4103](./Event-4103_PowerShell-Module-Logging/) | PowerShell Module Logging | PS/Operational | 🔴 Tier 1 | High |

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

---

## Priority Reference for SOC

When triaging alerts in this category, focus in this order:

1. **4688** – New Process Created (command line + parent process chain)
2. **4104** – PowerShell Script Block (full script content — highest value)
3. **4698** – Scheduled Task Created (persistence)
4. **4702** – Scheduled Task Modified (task hijacking)
5. **4103** – PowerShell Module Logging (cmdlet tracking)
6. **4699** – Scheduled Task Deleted (attacker cleanup)
7. **4689** – Process Exited (pair with 4688 for timeline)
8. **4700/4701** – Task Enabled/Disabled (evasion and security tool tampering)
