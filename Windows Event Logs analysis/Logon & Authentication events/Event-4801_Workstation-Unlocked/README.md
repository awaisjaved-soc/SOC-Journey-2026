# Event 4801 – Workstation Unlocked

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4801 |
| **Category** | Logon & Authentication |
| **Log** | Security |
| **SOC Importance** | 🟢 Low to Medium |

## What Is This Event?

Event 4801 is generated when a **locked workstation is unlocked**. It records who unlocked the computer and when.

This is the companion event to Event 4800 (Workstation Locked). Together they provide a complete picture of when a workstation was in use versus idle.

---

## Related Event

| Event ID | Meaning |
|----------|---------|
| **4800** | Workstation was **locked** |
| **4801** | Workstation was **unlocked** |

---

## How to Generate This Event

### Process (Lock First, Then Unlock)

**Step 1 – Lock the workstation:**
```powershell
# Method 1: Keyboard shortcut
# Press Win + L

# Method 2: PowerShell
rundll32.exe user32.dll,LockWorkStation
```
---

<img width="932" height="659" alt="image" src="https://github.com/user-attachments/assets/a5547520-13da-4c3b-bd2a-e71811b05632" />

---

**Step 2 – Unlock the workstation:**
1. Enter the password on the lock screen
2. Press Enter
3. Event 4801 is generated

---

<img width="1259" height="381" alt="image" src="https://github.com/user-attachments/assets/e6bf9a6d-04d0-4b4f-9227-68fcaa999ed8" />

---

## Enable Audit Policy (If Event Not Generating)

```powershell
# Enable the required audit subcategory
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
gpupdate /force
```

---

## Detection Command

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4801
} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time   = $_.TimeCreated
        User   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        Domain = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetDomainName'}).'#text'
    }
} | Format-Table -AutoSize
```
---

<img width="1339" height="773" alt="image" src="https://github.com/user-attachments/assets/fae1f3d7-44c3-4a09-9022-26f0dda28e36" />

---

### Simple Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4801} -MaxEvents 5 | Format-List TimeCreated, Message
```

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/25/2026 11:50:08 PM
Event ID:      4801
Task Category: Other Logon/Logoff Events
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-LFHCJK09RND.techcorp.local
Description:
The workstation was unlocked.

Subject:
	Security ID:		TECHCORP\administrator
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x440D1
	Session ID:	1
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4801</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12551</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-26T06:50:08.9595367Z" />
    <EventRecordID>7238</EventRecordID>
    <Correlation ActivityID="{722bbdeb-1cc0-0002-febd-2b72c01cdd01}" />
    <Execution ProcessID="660" ThreadID="4308" />
    <Channel>Security</Channel>
    <Computer>WIN-LFHCJK09RND.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserSid">S-1-5-21-2393829360-1893506578-1941953886-500</Data>
    <Data Name="TargetUserName">administrator</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetLogonId">0x440d1</Data>
    <Data Name="SessionId">1</Data>
  </EventData>
</Event>
```

## SOC Analyst Notes

- **Primary use:** User activity timeline and forensic investigation.
- Pair with Event 4800 to calculate how long a workstation was locked.
- If a workstation is unlocked by a **different user** than who locked it, investigate further.

> **Lab Note:** Like 4800, Event 4801 is not always reliable on Domain Controllers. If it does not generate after a few attempts, confirm the audit policy is enabled. Both 4800 and 4801 are lower priority events — focus first on 4624, 4625, 4768, 4769, 4648, and 4672.

| Scenario | Risk |
|----------|------|
| User unlocks their own workstation | Normal |
| Workstation unlocked by a different user than who locked it | 🔴 Investigate |
| Unlock at unusual hours (e.g., 3 AM) | 🟡 Suspicious |
