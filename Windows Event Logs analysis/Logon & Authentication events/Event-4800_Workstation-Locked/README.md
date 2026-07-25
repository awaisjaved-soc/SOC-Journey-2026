# Event 4800 – Workstation Locked

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4800 |
| **Category** | Logon & Authentication |
| **Log** | Security |
| **SOC Importance** | 🟢 Low to Medium |

## What Is This Event?

Event 4800 is generated when a workstation (computer) is **locked**. It records who locked the computer and when.

This event is triggered when:
- User presses `Win + L`
- Screen saver activates and locks the screen
- User manually locks the computer from the Start menu

---

## Related Event

| Event ID | Meaning |
|----------|---------|
| **4800** | Workstation was **locked** |
| **4801** | Workstation was **unlocked** |

---

## Event Fields Explained

| Field | Example Value | Meaning |
|-------|---------------|---------|
| **Account Name** | administrator | Who locked the computer |
| **Account Domain** | TECHCORP | The domain name |
| **Logon ID** | 0x440D1 | Unique ID of the session |
| **Time** | 7/25/2026 10:57:45 PM | When the lock happened |

---

## How to Generate This Event

### Method 1 – Keyboard Shortcut (Easiest)
1. While logged in as any user
2. Press `Win + L`
3. Event 4800 is generated

### Method 2 – PowerShell
```powershell
# Lock the workstation
rundll32.exe user32.dll,LockWorkStation
```

### Method 3 – Force Lock via tsdiscon
```powershell
tsdiscon
```

---

## Enable Audit Policy (If Event Not Generating)

```powershell
# Enable the required audit subcategory
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
gpupdate /force
```

---

## Detection Command

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4800
} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time     = $_.TimeCreated
        User     = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        Domain   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetDomainName'}).'#text'
    }
} | Format-Table -AutoSize
```

### Simple Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4800} -MaxEvents 5 | Format-List TimeCreated, Message
```

---

## SOC Analyst Notes

- **Primary use:** Building a **user activity timeline** during incident investigations.
- Helps establish when someone was or wasn't at their workstation.
- Useful combined with 4801 (Workstation Unlocked) to determine session gaps.

> **Lab Note:** Event 4800 is sometimes unreliable on Domain Controllers. If it does not generate, confirm the audit policy is enabled. This event is lower priority than 4624, 4625, 4768, 4769, 4648, and 4672.

| Scenario | Risk |
|----------|------|
| User locks workstation during the day | Normal |
| Workstation locked for long unusual periods | 🟡 May indicate abandonment |
| Workstation locked/unlocked repeatedly in short bursts | 🟡 Worth noting in timeline |
