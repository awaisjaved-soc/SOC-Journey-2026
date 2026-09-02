# Event 4702 – Scheduled Task Modified

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4702 |
| **Category** | Process & System Events |
| **Log** | Security |
| **Tier** | 🟠 Tier 2 – High Value |
| **SOC Importance** | 🔴 High |

## What Is This Event?

Event 4702 is generated when an **existing scheduled task is modified**. This is a high-value event because attackers often prefer to **modify a legitimate existing task** rather than creating a new one — this keeps them under the radar since security tools may not flag changes to known tasks as aggressively as brand new task creations.

Any change to the task's action (what it runs), trigger (when it runs), or user context (who runs it) should be reviewed carefully.

---

## Setup – Must Do First

```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
gpupdate /force
```

---

## How to Generate This Event

### Method 1 – GUI
1. Open **Task Scheduler** (`taskschd.msc`)
2. Right-click `EnableTestTask` → **Properties**
3. Go to **Actions** tab → Edit → change the program to `cmd.exe`
4. Click **OK**

### Method 2 – PowerShell
```powershell
# Modify the task action (generates 4702)
Set-ScheduledTask -TaskName "EnableTestTask" -Action (New-ScheduledTaskAction -Execute "cmd.exe")
```

### Full Lab Sequence
```powershell
# Step 1 – Create a task (generates 4698)
$action = New-ScheduledTaskAction -Execute "calc.exe"
Register-ScheduledTask -TaskName "EnableTestTask" -Action $action

# Step 2 – Modify it (generates 4702)
Set-ScheduledTask -TaskName "EnableTestTask" -Action (New-ScheduledTaskAction -Execute "cmd.exe")
```

---

## Detection Commands

### Basic Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4702} -MaxEvents 5 |
Select-Object TimeCreated, Id, Message | Format-List
```

### Full Scheduled Task Event Timeline
```powershell
# See the full lifecycle of all scheduled task events
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4698,4699,4700,4701,4702
} -MaxEvents 20 |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated -Descending |
Format-Table -AutoSize -Wrap
```

---

## SOC Analyst Notes

### What to Look For

| Indicator | Risk |
|-----------|------|
| Task action changed to point to a different executable | 🔴 Payload swap |
| Task action now includes encoded PowerShell | 🔴 Obfuscated attack |
| Task user context changed to SYSTEM or Administrator | 🔴 Privilege escalation via task |
| Legitimate Windows task modified (not a custom one) | 🔴 Hijacking a system task |
| Modification outside business hours | 🟡 Suspicious |

### Attack Scenario – Task Hijacking

```
Attacker identifies legitimate task "GoogleUpdateTask"
    → Modifies the action from "GoogleUpdate.exe" to "C:\Temp\payload.exe"
    → Event 4702 fires
    → Task now runs attacker payload every time Google Update would have run
    → Looks legitimate from the task name alone
```

This is why 4702 is often more dangerous than 4698 — the attacker hides behind a trusted task name.

### Combined Detection with All 5 Scheduled Task Events

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4698,4699,4700,4701,4702
} -MaxEvents 20 |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated -Descending |
Format-Table -AutoSize -Wrap
```

### Related Events

| Event ID | Relationship |
|----------|-------------|
| 4698 | Original task creation |
| 4699 | Task deleted after modification |
| 4700 | Task re-enabled after being disabled |
| 4701 | Task disabled |
| 4688 | Process launched when modified task runs |
