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
