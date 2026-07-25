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

### Simple Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4779} -MaxEvents 5 | Format-List TimeCreated, Message
```

---

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
