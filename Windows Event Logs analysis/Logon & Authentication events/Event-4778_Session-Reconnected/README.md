# Event 4778 – Session Reconnected

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4778 |
| **Category** | Logon & Authentication |
| **Log** | Security |
| **SOC Importance** | 🟡 Medium |

## What Is This Event?

Event 4778 is generated when a user **reconnects to an existing session**, most commonly through **Remote Desktop Protocol (RDP)**. This means the user was disconnected earlier and has now reconnected to the same session (the session was kept alive on the server).

Useful for tracking RDP activity and detecting suspicious reconnections.

---

## Related Event

| Event ID | Meaning |
|----------|---------|
| **4778** | Session was **reconnected** |
| **4779** | Session was **disconnected** |

These two events always come as a pair in RDP investigations.

---

## How to Generate This Event

### Method 1 – RDP Connect/Disconnect/Reconnect (Recommended)

> **Pre-requisite:** Remote Desktop must be enabled on the server.

**Step 1 – Enable RDP on the Server:**
```powershell
# Enable Remote Desktop
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0

# Allow through firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Add users to Remote Desktop Users group
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "alexrivera" -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "Administrator" -ErrorAction SilentlyContinue

# Disable NLA temporarily (helps with connection issues)
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 0
```
---
<img width="1252" height="372" alt="image" src="https://github.com/user-attachments/assets/fd992bc4-bce3-4765-809b-5fcdade8542a" />

---

**Step 2 – Enable Required Audit Policy:**
```powershell
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
gpupdate /force
```
---
<img width="942" height="657" alt="image" src="https://github.com/user-attachments/assets/f9ecc096-eceb-47bc-999f-cc98d13e8f71" />

---
**Step 3 – Connect via RDP from Host:**
1. Press `Win + R` → type `mstsc` → press Enter
2. Computer: `<Server IP>` (get with `ipconfig` on server)
3. Username: `techcorp\Administrator`
4. Connect → Stay 10-15 seconds → **Disconnect** (close RDP window, do NOT sign out)
5. Connect again via RDP → This generates **Event 4778**

> **VirtualBox Note:** If your VM uses NAT (IP like `10.0.2.x`), RDP from the host won't work. Change the network adapter to **Bridged Adapter** in VirtualBox settings to get a real IP.

---

## Detection Command

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4778} -MaxEvents 5 |
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
```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/25/2026 10:50:54 PM
Event ID:      4778
Task Category: Other Logon/Logoff Events
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-LFHCJK09RND.techcorp.local
Description:
A session was reconnected to a Window Station.

Subject:
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x440D1

Session:
	Session Name:		RDP-Tcp#0

Additional Information:
	Client Name:		DESKTOP-7I433PO
	Client Address:		192.168.100.27

This event is generated when a user reconnects to an existing Terminal Services session, or when a user switches to an existing desktop using Fast User Switching.
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4778</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12551</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-26T05:50:54.1208543Z" />
    <EventRecordID>6597</EventRecordID>
    <Correlation ActivityID="{722bbdeb-1cc0-0002-febd-2b72c01cdd01}" />
    <Execution ProcessID="660" ThreadID="868" />
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

### Verify Audit Policy is Enabled
```powershell
auditpol /get /subcategory:"Other Logon/Logoff Events"
```

---

## SOC Analyst Notes

- **Normal behavior:** Users reconnecting to their own RDP sessions during work hours.
- Monitor for reconnections from **unexpected IP addresses** — could indicate session hijacking.
- Pair with Event 4779 to build a full RDP session timeline.

| Scenario | Risk |
|----------|------|
| User reconnects to their own session from known IP | Normal |
| Reconnection from unknown or foreign IP | 🔴 Possible session hijacking |
| Admin account reconnecting at 3 AM | 🟡 Investigate |
