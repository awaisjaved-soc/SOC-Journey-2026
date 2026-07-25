# Event 4779 – Session Disconnected

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4779 |
| **Category** | Logon & Authentication |
| **Log** | Security |
| **SOC Importance** | 🟡 Medium |

## What Is This Event?

Event 4779 is generated when a user **disconnects from a session** (usually RDP) **without logging off**. The session remains active on the server even after the user closes their RDP window.

This is the companion event to Event 4778 (Session Reconnected). Together they track the full lifecycle of remote sessions.

---

## Related Event

| Event ID | Meaning |
|----------|---------|
| **4778** | Session was **reconnected** |
| **4779** | Session was **disconnected** |

---

<img width="938" height="664" alt="image" src="https://github.com/user-attachments/assets/9c0190d7-d92c-4dd7-8309-1cbdbd7ce50d" />

---
<img width="1249" height="359" alt="image" src="https://github.com/user-attachments/assets/c955a9a6-9642-48d5-9b15-5dcfc3de65d1" />

---
## How to Generate This Event

### Method – RDP Disconnect (Do NOT Sign Out)

> **Pre-requisite:** Remote Desktop must be enabled. See Event 4778 README for full setup steps.

1. Connect to the server via Remote Desktop
2. **Close the RDP window** (or click Disconnect in the Start menu)
3. Do **NOT** click Sign Out — just disconnect
4. Event 4779 is generated on the server

**Enable Audit Policy First (if events not generating):**
```powershell
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
gpupdate /force
```

---

## Detection Command

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4779} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time     = $_.TimeCreated
        User     = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        SourceIP = ($xml.Event.EventData.Data | Where {$_.Name -eq 'IpAddress'}).'#text'
    }
} | Format-Table -AutoSize
```
---

### Simple Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4779} -MaxEvents 5 | Format-List TimeCreated, Message
```

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/25/2026 10:57:44 PM
Event ID:      4779
Task Category: Other Logon/Logoff Events
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-LFHCJK09RND.techcorp.local
Description:
A session was disconnected from a Window Station.

Subject:
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x440D1

Session:
	Session Name:		RDP-Tcp#0

Additional Information:
	Client Name:		DESKTOP-7I433PO
	Client Address:		192.168.100.27


This event is generated when a user disconnects from an existing Terminal Services session, or when a user switches away from an existing desktop using Fast User Switching.
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4779</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12551</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-26T05:57:44.7148227Z" />
    <EventRecordID>6666</EventRecordID>
    <Correlation ActivityID="{722bbdeb-1cc0-0002-febd-2b72c01cdd01}" />
    <Execution ProcessID="660" ThreadID="792" />
    <Channel>Security</Channel>
    <Computer>WIN-LFHCJK09RND.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="AccountName">administrator</Data>
    <Data Name="AccountDomain">TECHCORP</Data>
    <Data Name="LogonID">0x440d1</Data>
    <Data Name="SessionName">RDP-Tcp#0</Data>
    <Data Name="ClientName">DESKTOP-7I433PO</Data>
    <Data Name="ClientAddress">192.168.100.27</Data>
  </EventData>
</Event>
```

## Lab Note

> Events 4778 and 4779 are not always reliable on Domain Controllers or VMs. If they do not generate after following all steps, verify the audit policy is enabled and try again. These events are **low-medium priority** compared to core events like 4624, 4625, 4768, 4769.

---

## SOC Analyst Notes

- Disconnected sessions stay **alive on the server** — this is a security concern if the session is not protected.
- An attacker with network access could reconnect to an abandoned session.
- Combine with Event 4778 to investigate suspicious remote session activity.

| Scenario | Risk |
|----------|------|
| User disconnects during work hours | Normal |
| Session disconnected, then reconnected from different IP | 🔴 Possible hijacking |
| Many disconnects/reconnects in short time | 🟡 Investigate |
