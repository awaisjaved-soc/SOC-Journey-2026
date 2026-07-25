# Event 4768 – Kerberos TGT Requested

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4768 |
| **Category** | Logon & Authentication |
| **Log** | Security |
| **SOC Importance** | 🟡 Medium |

## What Is This Event?

Event 4768 is generated when a **Kerberos Ticket Granting Ticket (TGT)** is requested. It is part of the normal Kerberos authentication process and shows the user requesting initial authentication from the Domain Controller.

### What Is Kerberos?
Kerberos is the main authentication system used in Windows domains. It uses **tickets** instead of sending passwords every time.

### What Is a TGT?
TGT = **Ticket Granting Ticket** — it is like a "master ticket" that proves:  
> *"I am really scott and I have already authenticated once."*

### How Event 4768 Works (Step by Step)

1. User tries to log in as `scott`
2. The computer asks the Domain Controller: *"Give me a TGT for scott"*
3. Domain Controller checks the password
4. If correct → It issues a TGT (**Event 4768 is generated**)
5. Later, when accessing another service, the TGT is used to get a service ticket (no password needed again)

**In simple terms:** Event 4768 = First step of Kerberos login (getting the master ticket)

**Useful for:** Baseline for normal authentication. Detecting abnormal Kerberos activity patterns.

---

## How to Generate This Event

### Method 1 – Manual (Recommended)
1. Log out completely
2. Log in as a domain user (e.g., `scott`)
3. Event 4768 is automatically generated

---


<img width="942" height="659" alt="image" src="https://github.com/user-attachments/assets/fbb1d121-9dd2-4ed0-8b21-ed2926051cfd" />

---

### Method 2 – PowerShell
```powershell
# Clear existing tickets and force a new TGT request
klist purge
klist
```

---

<img width="1230" height="386" alt="image" src="https://github.com/user-attachments/assets/67b045d9-a84a-446a-8697-f2e0d622ede7" />

---

## Detection Command

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time       = $_.TimeCreated
        User       = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        SourceIP   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'IpAddress'}).'#text'
    }
} | Format-Table -AutoSize
```

### Lab-Specific Detection Command (Part of Kerberos Lab)

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time       = $_.TimeCreated
        User       = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        SourceIP   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'IpAddress'}).'#text'
    }
} | Format-Table -AutoSize
```

---

```powershell

Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/26/2026 12:00:32 AM
Event ID:      4768
Task Category: Kerberos Authentication Service
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-LFHCJK09RND.techcorp.local
Description:
A Kerberos authentication ticket (TGT) was requested.

Account Information:
	Account Name:		Administrator
	Supplied Realm Name:	techcorp.local
	User ID:			TECHCORP\administrator

Service Information:
	Service Name:		krbtgt
	Service ID:		TECHCORP\krbtgt

Network Information:
	Client Address:		::1
	Client Port:		0

Additional Information:
	Ticket Options:		0x40810010
	Result Code:		0x0
	Ticket Encryption Type:	0x12
	Pre-Authentication Type:	2

Certificate Information:
	Certificate Issuer Name:		
	Certificate Serial Number:	
	Certificate Thumbprint:		

Certificate information is only provided if a certificate was used for pre-authentication.

Pre-authentication types, ticket options, encryption types and result codes are defined in RFC 4120.
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4768</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>14339</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-26T07:00:32.2960479Z" />
    <EventRecordID>7366</EventRecordID>
    <Correlation />
    <Execution ProcessID="660" ThreadID="7012" />
    <Channel>Security</Channel>
    <Computer>WIN-LFHCJK09RND.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserName">Administrator</Data>
    <Data Name="TargetDomainName">techcorp.local</Data>
    <Data Name="TargetSid">S-1-5-21-2393829360-1893506578-1941953886-500</Data>
    <Data Name="ServiceName">krbtgt</Data>
    <Data Name="ServiceSid">S-1-5-21-2393829360-1893506578-1941953886-502</Data>
    <Data Name="TicketOptions">0x40810010</Data>
    <Data Name="Status">0x0</Data>
    <Data Name="TicketEncryptionType">0x12</Data>
    <Data Name="PreAuthType">2</Data>
    <Data Name="IpAddress">::1</Data>
    <Data Name="IpPort">0</Data>
    <Data Name="CertIssuerName">
    </Data>
    <Data Name="CertSerialNumber">
    </Data>
    <Data Name="CertThumbprint">
    </Data>
  </EventData>
</Event>
```
## SOC Analyst Notes

- **Normal behavior:** Every domain user login generates a 4768.
- **What to look for in the event:**
  - `TargetUserName` = the user requesting the ticket (e.g., `scott`)
  - `IpAddress` = where the request came from

| Scenario | Risk |
|----------|------|
| User logs in from their usual workstation | Normal |
| Many 4768 events from unusual or unknown IPs | 🔴 Suspicious |
| 4768 at odd hours for sensitive accounts | 🟡 Investigate |
| TGT requests from non-domain IPs | 🔴 High Alert |
