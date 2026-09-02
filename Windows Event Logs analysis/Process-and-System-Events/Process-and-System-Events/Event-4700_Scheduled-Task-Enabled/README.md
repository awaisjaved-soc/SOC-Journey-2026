# Event 4700 – Scheduled Task Enabled

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4700 |
| **Category** | Process & System Events |
| **Log** | Security |
| **Tier** | 🟠 Tier 2 – High Value |
| **SOC Importance** | 🟡 Medium |

## What Is This Event?

Event 4700 is generated when a **previously disabled scheduled task is re-enabled**. Attackers may disable a task temporarily to avoid detection during an investigation, then re-enable it once they believe the threat has passed. This event is most useful when combined with Event 4701 (Task Disabled) to understand the full enable/disable lifecycle of a task.

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
2. Find any task (or create `EnableTestTask`)
3. Right-click → **Disable** (this generates Event 4701)
4. Right-click → **Enable** (this generates **Event 4700**)

### Method 2 – PowerShell (Full Sequence)
```powershell
# Step 1 – Create a task
$action = New-ScheduledTaskAction -Execute "calc.exe"
Register-ScheduledTask -TaskName "EnableTestTask" -Action $action

# Step 2 – Disable it first (generates 4701)
Disable-ScheduledTask -TaskName "EnableTestTask"

# Step 3 – Enable it (generates 4700)
Enable-ScheduledTask -TaskName "EnableTestTask"
```

---

## Detection Commands

### Basic Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4700} -MaxEvents 5 |
Select-Object TimeCreated, Id, Message | Format-List
```

### See Enable and Disable Together
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4700,4701} -MaxEvents 10 |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Format-Table -AutoSize -Wrap
```

---

## SOC Analyst Notes

| Scenario | Risk |
|----------|------|
| Task re-enabled after an incident was investigated | 🔴 Attacker returning |
| Task enabled by a non-admin user | 🔴 Unauthorized change |
| Enable/disable cycling on a task in short time | 🟡 Evasion technique |
| Security or backup task disabled then re-enabled | 🟡 Confirm with admin |

### Related Events

| Event ID | Relationship |
|----------|-------------|
| 4698 | Task originally created |
| 4701 | Task was disabled (pairs with 4700) |
| 4702 | Task was modified |
| 4699 | Task was deleted |
