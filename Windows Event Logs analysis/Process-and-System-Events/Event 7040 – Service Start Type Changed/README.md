# Event 7040 – Service Start Type Changed

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 7040 |
| **Category** | Process & System Events |
| **Log** | System |
| **Tier** | 🟠 Tier 2 – High Value |
| **SOC Importance** | 🔴 High |

## What Is This Event?

Event 7040 is generated when the **startup type of a service is changed**. For example changing from `Manual` to `Automatic`, or from `Automatic` to `Disabled`.

This is a high-value persistence and defense evasion event because:
- Attackers change a malicious service to `Automatic` so it **runs on every boot** without manual intervention
- Attackers change security services to `Disabled` so they **never start again** — permanently killing defenses
- Unlike just stopping a service (7036), changing the start type to `Disabled` is a permanent change that survives reboots

---

## Audit Policy

Event 7040 is logged in the **System log by default** — no audit policy required.

---

## How to Generate This Event

### Method 1 – GUI (Services Manager)
1. Press `Win + R` → type `services.msc` → Enter
2. Right-click any service → **Properties**
3. Change **Startup type** (e.g. from `Manual` to `Automatic`)
4. Click **Apply** → **OK**
5. Event 7040 is generated

### Method 2 – PowerShell
```powershell
# Create a test service
New-Service -Name "TestService7040" `
  -BinaryPathName "C:\Windows\System32\notepad.exe" `
  -StartupType Manual

# Change from Manual to Automatic (generates 7040)
Set-Service -Name "TestService7040" -StartupType Automatic

# Change back to Manual (generates another 7040)
Set-Service -Name "TestService7040" -StartupType Manual

# Disable completely (generates 7040 — most suspicious change)
Set-Service -Name "TestService7040" -StartupType Disabled
```

### Method 3 – sc.exe (Attacker Method)
```powershell
# Attackers typically use sc.exe for this
sc.exe config "TestService7040" start= auto
sc.exe config "TestService7040" start= disabled
```

### Method 4 – Simulate Attacker Enabling Persistence
```powershell
# Create service with manual start then make it auto (persistence)
New-Service -Name "WindowsUpdateSvc" `
  -BinaryPathName "C:\Users\Public\payload.exe" `
  -StartupType Manual

sc.exe config "WindowsUpdateSvc" start= auto
```

### Method 5 – Simulate Attacker Disabling a Security Service
```powershell
# DO THIS IN LAB ONLY — disable a test service, not a real security tool
sc.exe config "TestService7040" start= disabled
```

---

## How to Detect This Event

### GUI Method
1. Open **Event Viewer** (`eventvwr.msc`)
2. Go to **Windows Logs → System**
3. Click **Filter Current Log**
4. Enter Event ID: `7040`
5. Click OK

### PowerShell Method
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7040} -MaxEvents 10 |
ForEach-Object {
    [PSCustomObject]@{
        Time    = $_.TimeCreated
        Message = $_.Message
    }
} | Format-Table -AutoSize -Wrap
```

### Detect Security Services Being Disabled
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7040} -MaxEvents 30 |
Where-Object {
    $_.Message -match "disabled|Defender|WinDefend|EventLog|Firewall|MsMpEng|Wazuh"
} | Select-Object TimeCreated, Message | Format-List
```

### Full Service Events Timeline (All 5 Events Together)
```powershell
# System log — all service events together
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Id = 7000,7036,7040,7045
} -MaxEvents 20 |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated -Descending |
Format-Table -AutoSize -Wrap

# Security log — service installation
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4697
} -MaxEvents 5 |
Select-Object TimeCreated, Id, Message | Format-List
```

---

## Cleanup After Lab

```powershell
sc.exe delete "TestService7040"
sc.exe delete "WindowsUpdateSvc"
```

---

## SOC Analyst Notes

### What to Look For

| Change | Risk |
|--------|------|
| Unknown service changed to `Automatic` | 🔴 Persistence being set up |
| Security service changed to `Disabled` | 🔴 Defense evasion — critical |
| Windows Defender start type changed | 🔴 Investigate immediately |
| Windows Event Log start type changed | 🔴 Attacker trying to kill logging |
| Change happens at midnight or odd hours | 🟡 Suspicious |
| Admin changes start type during maintenance | 🟢 Normal — verify with change records |

### Start Type Reference

| Value | Meaning | Risk in SOC Context |
|-------|---------|---------------------|
| `Automatic` | Starts at every boot | 🔴 Used for persistence |
| `Manual` | Only starts when called | 🟢 Normal |
| `Disabled` | Cannot start at all | 🔴 Used to kill security tools |
| `Automatic (Delayed)` | Starts after boot completes | 🟡 Check what service |

### Attack Scenario

```
Attacker installs malicious service (7045)
    → Service set to Manual by default
    → Attacker runs: sc.exe config "MalSvc" start= auto
    → Event 7040 fires: start type changed to Automatic
    → Service now survives every reboot automatically
    → Analyst catches it by correlating 7045 + 7040
```

### Related Events

| Event ID | Log | Relationship |
|----------|-----|-------------|
| 7045 | System | Service installed (start type set at creation) |
| 4697 | Security | Security log version of installation |
| 7036 | System | Service started/stopped after type change |
| 7000 | System | Service failed to start |
