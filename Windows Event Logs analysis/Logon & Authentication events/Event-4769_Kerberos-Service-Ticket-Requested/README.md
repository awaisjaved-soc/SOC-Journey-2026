# Event 4769 – Kerberos Service Ticket Requested

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4769 |
| **Category** | Logon & Authentication |
| **Log** | Security |
| **SOC Importance** | 🔴 High |

## What Is This Event?

Event 4769 is generated when a **Kerberos Service Ticket** is requested to access a specific service (e.g., a file share or RDP session). After a user has a TGT (from Event 4768), they use it to request service tickets for specific resources — this is what 4769 records.

This is a critical event for detecting **Kerberoasting** attacks, where attackers request many service tickets to crack service account passwords offline.

---

## How to Generate This Event

### Method 1 – Access a Network Share (as alexrivera or scott)
```powershell
# Run while logged in as a domain user
dir \\WIN-KAHJ94DKN9V\c$
```
---

<img width="936" height="656" alt="image" src="https://github.com/user-attachments/assets/e0125dbb-d24d-411a-a960-bddd924de3e2" />

---
<img width="1262" height="384" alt="image" src="https://github.com/user-attachments/assets/80e6a928-cffb-4d29-9a6d-ec2c24c2caef" />


Or open **File Explorer** and navigate to:
```
\\WIN-KAHJ94DKN9V\c$
```

### Method 2 – RDP to Another Machine
1. Connect via Remote Desktop to another domain machine
2. A service ticket is automatically requested

---

## Detection Commands

### Basic Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time       = $_.TimeCreated
        User       = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        Service    = ($xml.Event.EventData.Data | Where {$_.Name -eq 'ServiceName'}).'#text'
    }
} | Format-Table -AutoSize
```
---
<img width="974" height="522" alt="image" src="https://github.com/user-attachments/assets/4858a1a6-899c-46f9-9047-c268d3e42176" />


---
### Extended Detection (with Source IP)
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 10 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time       = $_.TimeCreated
        User       = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        Service    = ($xml.Event.EventData.Data | Where {$_.Name -eq 'ServiceName'}).'#text'
        SourceIP   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'IpAddress'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## Kerberoasting Attack – Lab Simulation

Kerberoasting is an attack where an attacker requests many service tickets and then cracks them offline to obtain service account passwords.

### Safe Simulation Script
```powershell
# Simulate Kerberoasting (requesting service tickets in bulk)
$serviceAccounts = "scott","alexrivera"

foreach ($user in $serviceAccounts) {
    for ($i=1; $i -le 5; $i++) {
        $null = klist get "HTTP/fake.service.techcorp.local" 2>$null
        Start-Sleep -Milliseconds 300
    }
}
```


```powershell

Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/25/2026 11:50:47 PM
Event ID:      4769
Task Category: Kerberos Service Ticket Operations
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-LFHCJK09RND.techcorp.local
Description:
A Kerberos service ticket was requested.

Account Information:
	Account Name:		Administrator@TECHCORP.LOCAL
	Account Domain:		TECHCORP.LOCAL
	Logon GUID:		{65f4798e-19b7-fe3f-71f8-f6df3568d74a}

Service Information:
	Service Name:		WIN-LFHCJK09RND$
	Service ID:		TECHCORP\WIN-LFHCJK09RND$

Network Information:
	Client Address:		::1
	Client Port:		0

Additional Information:
	Ticket Options:		0x40810000
	Ticket Encryption Type:	0x12
	Failure Code:		0x0
	Transited Services:	-

This event is generated every time access is requested to a resource such as a computer or a Windows service.  The service name indicates the resource to which access was requested.

This event can be correlated with Windows logon events by comparing the Logon GUID fields in each event.  The logon event occurs on the machine that was accessed, which is often a different machine than the domain controller which issued the service ticket.

Ticket options, encryption types, and failure codes are defined in RFC 4120.
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4769</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>14337</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-26T06:50:47.3771062Z" />
    <EventRecordID>7271</EventRecordID>
    <Correlation />
    <Execution ProcessID="660" ThreadID="1184" />
    <Channel>Security</Channel>
    <Computer>WIN-LFHCJK09RND.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserName">Administrator@TECHCORP.LOCAL</Data>
    <Data Name="TargetDomainName">TECHCORP.LOCAL</Data>
    <Data Name="ServiceName">WIN-LFHCJK09RND$</Data>
    <Data Name="ServiceSid">S-1-5-21-2393829360-1893506578-1941953886-1000</Data>
    <Data Name="TicketOptions">0x40810000</Data>
    <Data Name="TicketEncryptionType">0x12</Data>
    <Data Name="IpAddress">::1</Data>
    <Data Name="IpPort">0</Data>
    <Data Name="Status">0x0</Data>
    <Data Name="LogonGuid">{65f4798e-19b7-fe3f-71f8-f6df3568d74a}</Data>
    <Data Name="TransmittedServices">-</Data>
  </EventData>
</Event>
```
This will generate multiple **4769** events in a short period — which is exactly the pattern SOC analysts look for.

---

## SOC Analyst Notes

### Detection Indicators for Kerberoasting

| Indicator | Description |
|-----------|-------------|
| Many 4769 events in short time | Bulk service ticket requests |
| Tickets requested for user accounts (not machine accounts) | Targeting service accounts |
| Unusual source IP | Requests from unexpected workstations |
| RC4 encryption used (etype 0x17) | Weak encryption chosen for offline cracking |

### Prevention
- Use **strong, long, complex passwords** for all service accounts
- Enable **"Account is sensitive and cannot be delegated"** on privileged accounts
- Use **Group Managed Service Accounts (gMSA)** — passwords are auto-managed
- Forward 4769 events to your **SIEM (e.g., Wazuh)** and alert on bulk requests

> **Note:** Service name may appear as an SPN like `cifs/WIN-KAHJ94DKN9V.techcorp.local` — this is normal Kerberos formatting.
