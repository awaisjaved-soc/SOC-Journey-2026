# Event 4103 – PowerShell Module Logging

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4103 |
| **Category** | Process & System Events |
| **Log** | Microsoft-Windows-PowerShell/Operational |
| **Tier** | 🔴 Tier 1 – Critical |
| **SOC Importance** | 🔴 High |

## What Is This Event?

Event 4103 logs **PowerShell module and pipeline execution details**. It shows which cmdlets, functions, and modules were used during a PowerShell session. While Event 4104 captures the full script block content, Event 4103 tracks the execution of individual pipeline commands and module activity.

Together, 4103 and 4104 give you complete visibility into PowerShell activity on a system.

### 4103 vs 4104 – Key Difference

| Feature | 4103 | 4104 |
|---------|------|------|
| What it logs | Pipeline/module execution | Full script block content |
| Detail level | Medium | High |
| Encoded commands | Shows command | Shows decoded content |
| Best for | Tracking cmdlet usage | Detecting obfuscated attacks |
| Priority | Secondary | Primary |

---

## Setup – Must Do First

Run these commands as **Administrator**:

```powershell
# Step 1 – Enable Module Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1

# Step 2 – Apply to ALL modules (wildcard)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*"

gpupdate /force
```

### Verify the Settings are Applied

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
```

> **Note:** Open a **new PowerShell window** after enabling. The setting does not apply to already-open sessions.

---

## How to Generate This Event

### Method 1 – Basic Commands
```powershell
Get-Process
Get-Service
Get-ChildItem C:\
```

### Method 2 – More Commands to Generate Multiple Events
```powershell
Get-LocalUser
Get-NetIPAddress
Get-ScheduledTask
Get-WmiObject -Class Win32_OperatingSystem
```

### Method 3 – Simulate Attacker Reconnaissance
```powershell
# These are all common attacker recon commands
whoami
Get-LocalGroupMember -Group "Administrators"
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'}
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
```

---

## Detection Commands

### Basic Detection
```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4103]]" -MaxEvents 5 |
Select-Object TimeCreated, Message | Format-List
```

### Search for Suspicious Module Activity
```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4103]]" -MaxEvents 30 |
Where-Object {
    $_.Message -match "ActiveDirectory|NetSecurity|Defender|Get-LocalGroup|Get-NetTCPConnection"
} | Select-Object TimeCreated, Message | Format-List
```

---

## SOC Analyst Notes

### Modules That Should Raise Flags

| Module / Cmdlet | Why It's Suspicious |
|----------------|---------------------|
| `ActiveDirectory` module commands | Possible AD enumeration |
| `Get-ADUser -Filter *` | Dumping all AD users |
| `Get-LocalGroupMember` | Checking who is admin |
| `Get-NetTCPConnection` | Network recon |
| `Invoke-WmiMethod` | WMI-based lateral movement |
| `Set-MpPreference` | Modifying Windows Defender settings |
| `Add-MpPreference -ExclusionPath` | Adding AV exclusion for malware |

### Event Log Location

Same as 4104 — in the PowerShell Operational log:

```
Event Viewer → Applications and Services Logs
    → Microsoft → Windows → PowerShell → Operational
```

### Enable Both 4103 and 4104 Together

For full PowerShell visibility, always enable both:

```powershell
# Script Block Logging (4104)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Module Logging (4103)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*"

gpupdate /force
```
