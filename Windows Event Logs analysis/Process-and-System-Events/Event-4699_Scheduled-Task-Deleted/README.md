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

---

<img width="809" height="423" alt="Screenshot_1" src="https://github.com/user-attachments/assets/783b4e2e-867c-47f9-a7e7-756536f77ee9" />

---

### Method 2 – PowerShell
```powershell
Unregister-ScheduledTask -TaskName "TestTask4698" -Confirm:$false
```
---

<img width="627" height="421" alt="Screenshot_14" src="https://github.com/user-attachments/assets/d69ccc4c-e640-41c9-81cb-67510eab4357" />

---
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
---
<img width="677" height="283" alt="Screenshot_3" src="https://github.com/user-attachments/assets/8b1a01a3-c2ac-4f8f-8bd7-4d2cbd5f452c" />

---

### Correlate 4698 and 4699 Together
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698,4699} -MaxEvents 10 |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Format-Table -AutoSize -Wrap
```

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          9/2/2026 9:50:22 PM
Event ID:      4699
Task Category: Other Object Access Events
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-LFHCJK09RND.techcorp.local
Description:
A scheduled task was deleted.

Subject:
	Security ID:		TECHCORP\administrator
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x2970A4

Task Information:
	Task Name: 		\TestTask4698
	Task Content: 		

Other Information:
	ProcessCreationTime: 		3659174697238867
	ClientProcessId: 			3904
	ParentProcessId: 			6476
	FQDN: 		0
	
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4699</EventID>
    <Version>1</Version>
    <Level>0</Level>
    <Task>12804</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-03T04:50:22.2760626Z" />
    <EventRecordID>12113</EventRecordID>
    <Correlation ActivityID="{243ab529-3b5d-0002-9cb5-3a245d3bdd01}" />
    <Execution ProcessID="684" ThreadID="892" />
    <Channel>Security</Channel>
    <Computer>WIN-LFHCJK09RND.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-2393829360-1893506578-1941953886-500</Data>
    <Data Name="SubjectUserName">administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x2970a4</Data>
    <Data Name="TaskName">\TestTask4698</Data>
    <Data Name="TaskContent">
    </Data>
    <Data Name="ClientProcessStartKey">3659174697238867</Data>
    <Data Name="ClientProcessId">3904</Data>
    <Data Name="ParentProcessId">6476</Data>
    <Data Name="RpcCallClientLocality">0</Data>
    <Data Name="FQDN">WIN-LFHCJK09RND.techcorp.local</Data>
  </EventData>
</Event>
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
