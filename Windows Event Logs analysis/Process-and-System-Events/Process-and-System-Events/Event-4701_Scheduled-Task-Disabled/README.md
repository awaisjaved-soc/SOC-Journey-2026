# Event 4701 – Scheduled Task Disabled

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4701 |
| **Category** | Process & System Events |
| **Log** | Security |
| **Tier** | 🟠 Tier 2 – High Value |
| **SOC Importance** | 🟡 Medium |

## What Is This Event?

Event 4701 is logged when a **scheduled task is disabled**. While this is often a legitimate administrative action, attackers may disable security-related or monitoring tasks to reduce visibility and avoid detection. SOC analysts should investigate when critical system tasks are disabled — especially by non-admin users or during unusual hours.

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
2. Find the task `EnableTestTask` (or any task)
3. Right-click → **Disable**

### Method 2 – PowerShell
```powershell
Disable-ScheduledTask -TaskName "EnableTestTask"
```

### Full Lab Sequence
```powershell
# Create task first
$action = New-ScheduledTaskAction -Execute "calc.exe"
Register-ScheduledTask -TaskName "EnableTestTask" -Action $action

# Disable the task (generates 4701)
Disable-ScheduledTask -TaskName "EnableTestTask"
```

---

## Detection Commands

### Basic Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4701} -MaxEvents 5 |
Select-Object TimeCreated, Id, Message | Format-List
```

---

## SOC Analyst Notes

| Scenario | Risk |
|----------|------|
| Windows Defender or backup task disabled | 🔴 Attacker disabling security |
| Task disabled by a non-admin | 🔴 Unauthorized change |
| Task disabled outside business hours | 🟡 Suspicious |
| Admin disabling a test or temp task | 🟢 Normal — verify with admin |

> **Key question in any investigation:** Which task was disabled, who disabled it, and does that match authorized change management records?
