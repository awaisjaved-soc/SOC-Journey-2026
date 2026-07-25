# Event 4800 – Workstation Locked

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4800 |
| **Category** | Logon & Authentication |
| **Log** | Security |
| **SOC Importance** | 🟢 Low to Medium |

## What Is This Event?

Event 4800 is generated when a workstation (computer) is **locked**. It records who locked the computer and when.

This event is triggered when:
- User presses `Win + L`
- Screen saver activates and locks the screen
- User manually locks the computer from the Start menu

---

## Related Event

| Event ID | Meaning |
|----------|---------|
| **4800** | Workstation was **locked** |
| **4801** | Workstation was **unlocked** |

---

## Event Fields Explained

| Field | Example Value | Meaning |
|-------|---------------|---------|
| **Account Name** | administrator | Who locked the computer |
| **Account Domain** | TECHCORP | The domain name |
| **Logon ID** | 0x440D1 | Unique ID of the session |
| **Time** | 7/25/2026 10:57:45 PM | When the lock happened |

---

## How to Generate This Event

### Method 1 – Keyboard Shortcut (Easiest)
1. While logged in as any user
2. Press `Win + L`
3. Event 4800 is generated

---

<img width="625" height="438" alt="image" src="https://github.com/user-attachments/assets/fa1378da-d73c-41ee-a99c-0d1aa7de60c1" />

---


### Method 2 – PowerShell
```powershell
# Lock the workstation
rundll32.exe user32.dll,LockWorkStation
```
---


<img width="1245" height="370" alt="image" src="https://github.com/user-attachments/assets/757c464f-4f05-419f-a3f3-4a5102adcaff" />

---
### Method 3 – Force Lock via tsdiscon
```powershell
tsdiscon
```

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
    Id = 4800
} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time     = $_.TimeCreated
        User     = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        Domain   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetDomainName'}).'#text'
    }
} | Format-Table -AutoSize
```

---

<img width="1327" height="572" alt="image" src="https://github.com/user-attachments/assets/d8c8457f-b3f4-4ca3-97d2-86b43fcee0da" />

---

### Simple Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4800} -MaxEvents 5 | Format-List TimeCreated, Message
```

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/25/2026 10:57:45 PM
Event ID:      4800
Task Category: Other Logon/Logoff Events
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-LFHCJK09RND.techcorp.local
Description:
The workstation was locked.

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
    <EventID>4800</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12551</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-26T05:57:45.1237901Z" />
    <EventRecordID>6667</EventRecordID>
    <Correlation ActivityID="{722bbdeb-1cc0-0002-febd-2b72c01cdd01}" />
    <Execution ProcessID="660" ThreadID="868" />
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
```

## SOC Analyst Notes

- **Primary use:** Building a **user activity timeline** during incident investigations.
- Helps establish when someone was or wasn't at their workstation.
- Useful combined with 4801 (Workstation Unlocked) to determine session gaps.

> **Lab Note:** Event 4800 is sometimes unreliable on Domain Controllers. If it does not generate, confirm the audit policy is enabled. This event is lower priority than 4624, 4625, 4768, 4769, 4648, and 4672.

| Scenario | Risk |
|----------|------|
| User locks workstation during the day | Normal |
| Workstation locked for long unusual periods | 🟡 May indicate abandonment |
| Workstation locked/unlocked repeatedly in short bursts | 🟡 Worth noting in timeline |
