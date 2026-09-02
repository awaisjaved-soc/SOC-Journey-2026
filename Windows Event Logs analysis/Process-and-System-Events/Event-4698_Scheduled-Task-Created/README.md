# Event 4698 – Scheduled Task Created

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4698 |
| **Category** | Process & System Events |
| **Log** | Security |
| **Tier** | 🟠 Tier 2 – High Value |
| **SOC Importance** | 🔴 High |

## What Is This Event?

Event 4698 is generated whenever a **new scheduled task is created** on the system. Scheduled tasks are one of the most common persistence techniques used by attackers. Malware and threat actors frequently create scheduled tasks so their payload runs automatically — even after the system reboots or the user logs off.

In a SOC environment, this event should be closely monitored, especially when tasks are created by unusual users, from unexpected locations, or with suspicious command lines pointing to scripts or binaries in temp folders.

---

## Setup – Must Do First

Run this command as **Administrator** before generating or detecting this event:

```powershell
# Enable auditing for Scheduled Task events
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
gpupdate /force
```

### Verify the Policy is Active

```powershell
auditpol /get /subcategory:"Other Object Access Events"
```

Expected output: `Other Object Access Events   Success and Failure`

---

## How to Generate This Event

### Method 1 – GUI (Task Scheduler)
1. Open **Task Scheduler** — press `Win + R` → type `taskschd.msc` → Enter
2. Click **Create Basic Task** in the right panel
3. Name it `TestTask4698`
4. Set trigger to **"When I log on"**
5. Action → **Start a program** → enter `notepad.exe`
6. Click **Finish**

### Method 2 – PowerShell (Standard)
```powershell
$action = New-ScheduledTaskAction -Execute "notepad.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "TestTask4698" -Action $action -Trigger $trigger -Description "SOC Lab Test Task"
```

### Method 3 – PowerShell (Visible Task – Runs on Screen)
By default, tasks run under the SYSTEM account which has no desktop — so Notepad won't appear on screen. Use this method to create a visible task:

```powershell
$action = New-ScheduledTaskAction -Execute "notepad.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "Administrator" -LogonType Interactive -RunLevel Highest

Register-ScheduledTask -TaskName "VisibleNotepadTask" -Action $action -Trigger $trigger -Principal $principal -Description "Visible Task for Lab"
```

Then go to Task Scheduler → Right-click **VisibleNotepadTask** → **Run** — Notepad will open on screen.

---

## Common Issue – Notepad Not Appearing on Screen

If you create a task and run it but Notepad does not open, this is expected behavior. Here is why and how to fix it:

**Why this happens:** Scheduled tasks run under the **SYSTEM** account by default. The SYSTEM account has no desktop session, so GUI programs like Notepad run invisibly in the background.

**Fix via Task Scheduler GUI:**
1. Open Task Scheduler → Find your task → Right-click → **Properties**
2. **General Tab:** Select **"Run only when user is logged on"** and check **"Run with highest privileges"**
3. **Conditions Tab:** Uncheck everything (especially "Start only if on AC power")
4. **Settings Tab:** Check **"Allow task to be run on demand"**
5. Click **OK** → Right-click the task → **Run**

---

## Detection Commands

### Basic Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} -MaxEvents 5 |
Select-Object TimeCreated, Id, Message | Format-List
```

### Extended Detection with XML Parsing
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time     = $_.TimeCreated
        TaskName = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TaskName'}).'#text'
        User     = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## SOC Analyst Notes

### What to Look For

| Indicator | Risk |
|-----------|------|
| Task created by a non-admin user | 🔴 Investigate immediately |
| Task command points to `%TEMP%`, `%APPDATA%`, or `C:\Users\Public` | 🔴 Malware dropper |
| Task created outside business hours | 🟡 Suspicious |
| Task runs `powershell.exe`, `cmd.exe`, or `wscript.exe` with arguments | 🔴 Likely malicious |
| Task name looks like a legitimate Windows task but is slightly different | 🔴 Masquerading |
| Task created right after a failed login or phishing email | 🔴 Compromise in progress |

### Attack Scenario

```
Attacker gets foothold
    → Drops payload to C:\Users\Public\update.exe
    → Creates scheduled task: schtasks /create /tn "WindowsUpdate" /tr "C:\Users\Public\update.exe" /sc onlogon
    → Event 4698 fires
    → Analyst sees task with suspicious path and unusual name
```

### Related Events

| Event ID | Relationship |
|----------|-------------|
| 4699 | Task was deleted (attacker cleaning up) |
| 4700 | Task was enabled |
| 4701 | Task was disabled |
| 4702 | Task was modified |
| 4688 | Process created when the task runs |
