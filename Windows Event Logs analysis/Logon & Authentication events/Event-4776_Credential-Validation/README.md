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

## Event Fields Explained

| Field | Example Value | Meaning |
|-------|---------------|---------|
| **Logon Account** | Administrator | The account whose credentials were checked |
| **Source Workstation** | DESKTOP-7I433PO | The computer that sent the authentication request |
| **Authentication Package** | MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 | NTLM authentication was used |
| **Error Code** | 0x0 | **Success** (0x0 = credentials were valid) |
| **Time** | 7/25/2026 10:57:56 PM | When the validation happened |

---

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
