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

### Method 2 – PowerShell
```powershell
# Clear existing tickets and force a new TGT request
klist purge
klist
```

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
