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

---

<img width="804" height="426" alt="Screenshot_1" src="https://github.com/user-attachments/assets/5834a280-1029-4fa0-afa6-79fc8e65e1f6" />

---

<img width="814" height="427" alt="Screenshot_5" src="https://github.com/user-attachments/assets/601fcd9d-bce5-4231-9ecc-eb452f428ccc" />


---


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

<img width="474" height="335" alt="Screenshot_3" src="https://github.com/user-attachments/assets/eb9c8f7d-bb74-49b6-b2eb-68c0b3d09ea5" />

---

<img width="469" height="332" alt="Screenshot_4" src="https://github.com/user-attachments/assets/09af0945-06ed-421c-96e0-6e73501ad6c1" />


---


## Detection Commands

### Basic Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4702} -MaxEvents 5 |
Select-Object TimeCreated, Id, Message | Format-List
```

---

<img width="623" height="250" alt="Screenshot_2" src="https://github.com/user-attachments/assets/0aa2caca-9372-468a-8c62-a364d8cee102" />

---

<img width="676" height="382" alt="Screenshot_6" src="https://github.com/user-attachments/assets/2f77a30f-b8b8-45b3-8017-16ae2e872cdb" />

---

<img width="678" height="388" alt="Screenshot_7" src="https://github.com/user-attachments/assets/a803ea53-01d9-49ee-970d-a04f1ac02cc1" />


---

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
