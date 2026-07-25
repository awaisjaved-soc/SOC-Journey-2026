# Event 4672 – Special Privileges Assigned

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4672 |
| **Category** | Logon & Authentication |
| **Log** | Security |
| **SOC Importance** | 🔴 High |

## What Is This Event?

Event 4672 is generated when a logon session is assigned **special (high-level) privileges** such as `SeDebugPrivilege`, `SeBackupPrivilege`, or other admin-level rights. It fires whenever an administrator or a process with elevated rights logs on.

This is **not** a normal user login event. It specifically records that the logon session received **powerful admin-level abilities**.

SOC analysts monitor this event closely because it often indicates privilege escalation or an attacker gaining admin-level access.

---

## Special Privileges Reference Table

| Privilege Name | Full Name | What It Allows | Danger Level |
|---|---|---|---|
| `SeDebugPrivilege` | Debug Programs | Read/write memory of any process | 🔴 Very High |
| `SeBackupPrivilege` | Backup Files and Directories | Bypass file permissions to read any file | 🔴 High |
| `SeRestorePrivilege` | Restore Files and Directories | Bypass permissions to write any file | 🔴 High |
| `SeTakeOwnershipPrivilege` | Take Ownership of Files | Take control of any file or folder | 🔴 High |
| `SeLoadDriverPrivilege` | Load and Unload Device Drivers | Install kernel-level drivers | 🔴 Critical |
| `SeTcbPrivilege` | Act as Part of the OS | Highest possible privilege | 🔴 Critical |
| `SeAssignPrimaryTokenPrivilege` | Replace Process Token | Replace default token of a process | 🔴 High |

---

## How to Generate This Event

### Method 1 – Manual GUI
1. Log in as **Administrator**
2. Event 4672 is automatically generated upon login with elevated privileges

### Method 2 – PowerShell
```powershell
# Run a command with elevated privileges
Start-Process powershell.exe -Verb RunAs
```

---

## Detection Command

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time       = $_.TimeCreated
        User       = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        Privileges = ($xml.Event.EventData.Data | Where {$_.Name -eq 'PrivilegeList'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## SOC Analyst Notes

- **Normal behavior:** Administrators will always trigger Event 4672 on login.
- **Red Flag:** Event 4672 for a **normal user** (like `scott` or `alexrivera`) with many dangerous privileges.
- **Red Flag:** 4672 fired at **odd hours** even for administrator accounts.
- **Attack Scenario:** Attacker logs in → Obtains `SeDebugPrivilege` → Uses tools like **Mimikatz** to dump credentials from memory.

### What to Look For

| Scenario | Risk |
|----------|------|
| Admin logs in during business hours | Normal |
| Normal user receives `SeDebugPrivilege` | 🔴 Investigate immediately |
| Admin account active at 3 AM | 🟡 Suspicious |
| Many privileges assigned to unknown account | 🔴 High Alert |
