# Event 4672 – Special Privileges Assigned

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4672 |
| **Category** | Logon & Authentication |
| **Log** | Security |
| **SOC Importance** | 🔴 High |

## What Is This Event?

Event 4672 is generated when a logon session is assigned **special (high-level) privileges** such as `SeDebugPrivilege`, `SeBackupPrivilege`, or other admin-level rights. It fires whenever an administrator or a process with elevated rights logs on.

This is **not** a normal user login event. It specifically records that the logon session received **powerful admin-level abilities**.

SOC analysts monitor this event closely because it often indicates privilege escalation or an attacker gaining admin-level access.

---

## Special Privileges Reference Table

| Privilege Name | Full Name | What It Allows | Danger Level |
|---|---|---|---|
| `SeDebugPrivilege` | Debug Programs | Read/write memory of any process | 🔴 Very High |
| `SeBackupPrivilege` | Backup Files and Directories | Bypass file permissions to read any file | 🔴 High |
| `SeRestorePrivilege` | Restore Files and Directories | Bypass permissions to write any file | 🔴 High |
| `SeTakeOwnershipPrivilege` | Take Ownership of Files | Take control of any file or folder | 🔴 High |
| `SeLoadDriverPrivilege` | Load and Unload Device Drivers | Install kernel-level drivers | 🔴 Critical |
| `SeTcbPrivilege` | Act as Part of the OS | Highest possible privilege | 🔴 Critical |
| `SeAssignPrimaryTokenPrivilege` | Replace Process Token | Replace default token of a process | 🔴 High |

---

## How to Generate This Event

### Method 1 – Manual GUI
1. Log in as **Administrator**
2. Event 4672 is automatically generated upon login with elevated privileges

---

<img width="932" height="654" alt="image" src="https://github.com/user-attachments/assets/6cc2fdc8-46d0-4606-84f5-8cd8881b43a6" />
---

### Method 2 – PowerShell
```powershell
# Run a command with elevated privileges
Start-Process powershell.exe -Verb RunAs
```
---

<img width="797" height="376" alt="image" src="https://github.com/user-attachments/assets/eeb8ce02-256f-4556-8b7b-05cd0e446d31" />


---

## Detection Command

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time       = $_.TimeCreated
        User       = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        Privileges = ($xml.Event.EventData.Data | Where {$_.Name -eq 'PrivilegeList'}).'#text'
    }
} | Format-Table -AutoSize
```

---
```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/26/2026 12:05:13 AM
Event ID:      4672
Task Category: Special Logon
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-LFHCJK09RND.techcorp.local
Description:
Special privileges assigned to new logon.

Subject:
	Security ID:		SYSTEM
	Account Name:		WIN-LFHCJK09RND$
	Account Domain:		TECHCORP
	Logon ID:		0x30AEBF

Privileges:		SeSecurityPrivilege
			SeBackupPrivilege
			SeRestorePrivilege
			SeTakeOwnershipPrivilege
			SeDebugPrivilege
			SeSystemEnvironmentPrivilege
			SeLoadDriverPrivilege
			SeImpersonatePrivilege
			SeDelegateSessionUserImpersonatePrivilege
			SeEnableDelegationPrivilege
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4672</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12548</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-26T07:05:13.0849643Z" />
    <EventRecordID>7412</EventRecordID>
    <Correlation />
    <Execution ProcessID="660" ThreadID="3240" />
    <Channel>Security</Channel>
    <Computer>WIN-LFHCJK09RND.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">WIN-LFHCJK09RND$</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x30aebf</Data>
    <Data Name="PrivilegeList">SeSecurityPrivilege
			SeBackupPrivilege
			SeRestorePrivilege
			SeTakeOwnershipPrivilege
			SeDebugPrivilege
			SeSystemEnvironmentPrivilege
			SeLoadDriverPrivilege
			SeImpersonatePrivilege
			SeDelegateSessionUserImpersonatePrivilege
			SeEnableDelegationPrivilege</Data>
  </EventData>
</Event>
```



## SOC Analyst Notes

- **Normal behavior:** Administrators will always trigger Event 4672 on login.
- **Red Flag:** Event 4672 for a **normal user** (like `scott` or `alexrivera`) with many dangerous privileges.
- **Red Flag:** 4672 fired at **odd hours** even for administrator accounts.
- **Attack Scenario:** Attacker logs in → Obtains `SeDebugPrivilege` → Uses tools like **Mimikatz** to dump credentials from memory.

### What to Look For

| Scenario | Risk |
|----------|------|
| Admin logs in during business hours | Normal |
| Normal user receives `SeDebugPrivilege` | 🔴 Investigate immediately |
| Admin account active at 3 AM | 🟡 Suspicious |
| Many privileges assigned to unknown account | 🔴 High Alert |
