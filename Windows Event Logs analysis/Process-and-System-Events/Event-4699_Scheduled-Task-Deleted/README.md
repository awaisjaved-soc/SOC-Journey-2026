# Event 4699 – Scheduled Task Deleted

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4699 |
| **Category** | Process & System Events |
| **Log** | Security |
| **Tier** | 🟠 Tier 2 – High Value |
| **SOC Importance** | 🟡 Medium–High |

## What Is This Event?

Event 4699 is logged when a **scheduled task is deleted** from the system. Attackers sometimes create a scheduled task for persistence and later delete it to cover their tracks after completing their objective.

In investigations, this event should be correlated with Event 4698 (Task Created) to determine what task was removed, who created it, and whether the deletion is part of a cleanup operation after an attack.

---

## Setup – Must Do First

```powershell
# Enable auditing for Scheduled Task events (same policy as 4698)
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
gpupdate /force
```

---

## How to Generate This Event

> **Pre-requisite:** You need an existing task. Create one first using Event 4698 lab steps.

### Method 1 – GUI
1. Open **Task Scheduler** (`taskschd.msc`)
2. Find the task `TestTask4698`
3. Right-click → **Delete**
4. Confirm the deletion

### Method 2 – PowerShell
```powershell
Unregister-ScheduledTask -TaskName "TestTask4698" -Confirm:$false
```

### Full Lab Sequence (Create then Delete)
```powershell
# Step 1 – Create the task (generates 4698)
$action = New-ScheduledTaskAction -Execute "notepad.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "TestTask4698" -Action $action -Trigger $trigger

# Step 2 – Delete the task (generates 4699)
Unregister-ScheduledTask -TaskName "TestTask4698" -Confirm:$false
```

---

## Detection Commands

### Basic Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4699} -MaxEvents 5 |
Select-Object TimeCreated, Id, Message | Format-List
```

### Correlate 4698 and 4699 Together
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698,4699} -MaxEvents 10 |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Format-Table -AutoSize -Wrap
```

---

## SOC Analyst Notes

### What to Look For

| Scenario | Risk |
|----------|------|
| Task deleted shortly after being created | 🔴 Classic attacker cleanup pattern |
| Task deleted by a different user than who created it | 🔴 Investigate both accounts |
| Task deleted during or after a security incident | 🔴 Evidence destruction |
| Admin deleting legitimate scheduled tasks | 🟡 Confirm with the admin |

### Attack Pattern

```
4698 – Task "WindowsUpdate" created by alexrivera at 02:13 AM
4688 – payload.exe launched at 02:14 AM
4699 – Task "WindowsUpdate" deleted by alexrivera at 02:15 AM
```

This sequence — create, execute, delete — is a textbook persistence-and-cleanup pattern that analysts must recognize.
