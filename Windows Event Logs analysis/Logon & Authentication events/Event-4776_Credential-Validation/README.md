# Event 4776 – Credential Validation

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4776 |
| **Category** | Logon & Authentication |
| **Log** | Security |
| **SOC Importance** | 🟡 Medium |

## What Is This Event?

Event 4776 is generated when the system (a Domain Controller or local computer) **validates the username and password** of an account using **NTLM authentication**.

In simple words: Windows is checking — *"Is this username + password correct?"*

This event is different from Kerberos events (4768/4769). Event 4776 specifically covers **NTLM-based credential validation**, which is common when:
- Logging into a local machine (not domain)
- Authenticating from a non-domain device
- Applications using NTLM instead of Kerberos

---
<img width="934" height="653" alt="image" src="https://github.com/user-attachments/assets/f7fe5dcc-d517-49a7-8d0b-828568205c50" />

---


## Event Fields Explained

| Field | Example Value | Meaning |
|-------|---------------|---------|
| **Logon Account** | Administrator | The account whose credentials were checked |
| **Source Workstation** | DESKTOP-7I433PO | The computer that sent the authentication request |
| **Authentication Package** | MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 | NTLM authentication was used |
| **Error Code** | 0x0 | **Success** (0x0 = credentials were valid) |
| **Time** | 7/25/2026 10:57:56 PM | When the validation happened |

---
```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/25/2026 10:57:56 PM
Event ID:      4776
Task Category: Credential Validation
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-LFHCJK09RND.techcorp.local
Description:
The computer attempted to validate the credentials for an account.

Authentication Package:	MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account:	Administrator
Source Workstation:	DESKTOP-7I433PO
Error Code:	0x0
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4776</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>14336</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-26T05:57:56.5342733Z" />
    <EventRecordID>6668</EventRecordID>
    <Correlation />
    <Execution ProcessID="660" ThreadID="792" />
    <Channel>Security</Channel>
    <Computer>WIN-LFHCJK09RND.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="PackageName">MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data>
    <Data Name="TargetUserName">Administrator</Data>
    <Data Name="Workstation">DESKTOP-7I433PO</Data>
    <Data Name="Status">0x0</Data>
  </EventData>
</Event>
```

## Error Codes Reference

| Error Code | Meaning |
|------------|---------|
| `0x0` | Success – credentials were valid |
| `0xC000006A` | Wrong password |
| `0xC0000064` | Username does not exist |
| `0xC0000234` | Account locked out |
| `0xC0000072` | Account disabled |

---

## Detection Command

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4776} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        Account     = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        Workstation = ($xml.Event.EventData.Data | Where {$_.Name -eq 'Workstation'}).'#text'
        ErrorCode   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'Status'}).'#text'
    }
} | Format-Table -AutoSize
```

### Filter Only Failed Validations
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4776} -MaxEvents 20 |
Where-Object {
    $xml = [xml]$_.ToXml()
    ($xml.Event.EventData.Data | Where {$_.Name -eq 'Status'}).'#text' -ne '0x0'
} | Format-List TimeCreated, Message
```

---

## SOC Analyst Notes

Use Event 4776 in combination with:
- **Event 4624** – Successful Logon (confirm auth succeeded)
- **Event 4625** – Failed Logon (confirm auth failed)

| Scenario | Risk |
|----------|------|
| `ErrorCode 0x0` for known admin from their workstation | Normal |
| `0xC000006A` repeated for the same account | 🟡 Possible brute-force |
| `0xC0000064` for many different usernames | 🔴 Username enumeration |
| Auth request from unknown workstation | 🟡 Investigate source |
