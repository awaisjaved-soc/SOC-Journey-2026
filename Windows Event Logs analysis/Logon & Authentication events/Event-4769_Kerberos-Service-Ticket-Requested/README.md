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
