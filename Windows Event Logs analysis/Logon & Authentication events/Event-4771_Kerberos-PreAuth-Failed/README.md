# Event 4771 – Kerberos Pre-Authentication Failed

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4771 |
| **Category** | Logon & Authentication |
| **Log** | Security |
| **SOC Importance** | 🟡 Medium |

## What Is This Event?

Event 4771 is generated when **Kerberos pre-authentication fails**. This typically happens when a wrong password is used during Kerberos authentication.

Pre-authentication is a security feature of Kerberos that requires the client to prove knowledge of the account password before a TGT is issued. When this fails, Event 4771 is logged.

**Can indicate:** Password guessing attacks or misconfigured accounts.

---

## How to Generate This Event

### Method 1 – Manual GUI
1. Attempt to log in to the domain with the **wrong password**
2. Kerberos is used by default in domain environments → Event 4771 is generated

### Method 2 – PowerShell
```powershell
$cred = New-Object System.Management.Automation.PSCredential(
    "scott",
    (ConvertTo-SecureString "WrongPass" -AsPlainText -Force)
)
Start-Process powershell.exe -Credential $cred -NoNewWindow -ErrorAction SilentlyContinue
```
---

<img width="634" height="445" alt="image" src="https://github.com/user-attachments/assets/f4e54acc-abb7-417a-b6f2-07230f9729c7" />

---


---

## Detection Command

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4771} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time       = $_.TimeCreated
        User       = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```
---

<img width="996" height="513" alt="image" src="https://github.com/user-attachments/assets/e465e84e-5d2a-46b3-8d6c-f8a3b1db3064" />

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/25/2026 8:56:16 PM
Event ID:      4771
Task Category: Kerberos Authentication Service
Level:         Information
Keywords:      Audit Failure
User:          N/A
Computer:      WIN-LFHCJK09RND.techcorp.local
Description:
Kerberos pre-authentication failed.

Account Information:
	Security ID:		TECHCORP\alexrivera
	Account Name:		alexrivera

Service Information:
	Service Name:		krbtgt/TECHCORP

Network Information:
	Client Address:		::1
	Client Port:		0

Additional Information:
	Ticket Options:		0x40810010
	Failure Code:		0x18
	Pre-Authentication Type:	2

Certificate Information:
	Certificate Issuer Name:		
	Certificate Serial Number: 	
	Certificate Thumbprint:		

Certificate information is only provided if a certificate was used for pre-authentication.

Pre-authentication types, ticket options and failure codes are defined in RFC 4120.

If the ticket was malformed or damaged during transit and could not be decrypted, then many fields in this event might not be present.
```

## SOC Analyst Notes

- A few 4771 events for a user = likely a typo, not a threat.
- **Many 4771 events in a short time for the same account** = possible brute-force or password spray attack.
- Pair with **Event 4625** (Failed Logon) to build a complete picture of failed authentication.

| Scenario | Risk |
|----------|------|
| One or two failed attempts | 🟢 Normal (user typo) |
| 5–10 failed attempts quickly for one account | 🟡 Investigate |
| Many failures across multiple accounts | 🔴 Password spray attack |
| Failures followed by successful 4768 | 🔴 Brute-force succeeded |
