# Event 4801 – Workstation Unlocked

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4801 |
| **Category** | Logon & Authentication |
| **Log** | Security |
| **SOC Importance** | 🟢 Low to Medium |

## What Is This Event?

Event 4801 is generated when a **locked workstation is unlocked**. It records who unlocked the computer and when.

This is the companion event to Event 4800 (Workstation Locked). Together they provide a complete picture of when a workstation was in use versus idle.

---

## Related Event

| Event ID | Meaning |
|----------|---------|
| **4800** | Workstation was **locked** |
| **4801** | Workstation was **unlocked** |

---

## How to Generate This Event

### Process (Lock First, Then Unlock)

**Step 1 – Lock the workstation:**
```powershell
# Method 1: Keyboard shortcut
# Press Win + L

# Method 2: PowerShell
rundll32.exe user32.dll,LockWorkStation
```

**Step 2 – Unlock the workstation:**
1. Enter the password on the lock screen
2. Press Enter
3. Event 4801 is generated

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
    Id = 4801
} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time   = $_.TimeCreated
        User   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        Domain = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetDomainName'}).'#text'
    }
} | Format-Table -AutoSize
```

### Simple Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4801} -MaxEvents 5 | Format-List TimeCreated, Message
```

---

## SOC Analyst Notes

- **Primary use:** User activity timeline and forensic investigation.
- Pair with Event 4800 to calculate how long a workstation was locked.
- If a workstation is unlocked by a **different user** than who locked it, investigate further.

> **Lab Note:** Like 4800, Event 4801 is not always reliable on Domain Controllers. If it does not generate after a few attempts, confirm the audit policy is enabled. Both 4800 and 4801 are lower priority events — focus first on 4624, 4625, 4768, 4769, 4648, and 4672.

| Scenario | Risk |
|----------|------|
| User unlocks their own workstation | Normal |
| Workstation unlocked by a different user than who locked it | 🔴 Investigate |
| Unlock at unusual hours (e.g., 3 AM) | 🟡 Suspicious |
