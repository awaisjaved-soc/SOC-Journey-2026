# Event ID 4609 — Windows Is Shutting Down

**Log:** Security  
**Category:** System  
**Subcategory:** Security State Change - 
**Level:** Information  
**Lab Environment:** Windows Server 2019 — TECHCORP / techcorp.local

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 4609 |
| Event Name | Windows is shutting down |
| Log Location | Windows Logs → Security |
| Audit Category | System |
| Audit Subcategory | Security State Change |
| Default State | Enabled by default — but unreliable on Windows Server |
| SACL Required | No |

---

## What Is Event 4609?

Event 4609 is the mirror of Event 4608. While 4608 marks the start of a Windows session in the Security log, 4609 is intended to mark the end — it fires when the LSA begins its shutdown sequence, just before the system powers off or restarts.

In theory, every clean shutdown should produce a 4609. In practice, this event is **highly unreliable on Windows Server**, and its absence should never be treated as evidence of an unclean shutdown. The reason is explained in detail below.

When 4609 does appear, it is used alongside 4608 to define the boundaries of a Windows session — the gap between them is the time the machine was running. It is also used to confirm that a shutdown was initiated through the normal Windows shutdown process rather than a forced kill.

---

## Why 4609 Is Unreliable — The Race Condition

This is the most important thing to understand about Event 4609, and it is the reason this event could not be consistently reproduced in this lab environment.

During the Windows shutdown sequence, two things need to happen in order:

```
Expected sequence:
LSA writes 4609 to Security log  →  Event Log service stops  →  6006 fires  →  power off

What actually happens on Windows Server:
Event Log service stops first  →  LSA tries to write 4609  →  no log service running  →  4609 lost
```

The Event Log service and the LSA both receive shutdown signals at roughly the same time. On Windows Server, the Event Log service frequently terminates before the LSA has finished writing 4609. Once the Event Log service is stopped, there is nowhere to write the event — it is lost permanently with no error and no recovery.

This is a known, documented behaviour that affects Windows Server 2016, 2019, and 2022. It is not a misconfiguration. It is not fixable through audit policy changes. It is a fundamental timing issue in the shutdown sequence.

**The practical replacement for 4609 is Event 6006** — the Event Log service writes 6006 to the System log as its very last action before stopping, making it far more reliable as a clean shutdown indicator.

---

## Lab Reproduction Note

> **Lab Note:** Event 4609 could not be consistently reproduced in this lab environment (Windows Server 2019, VirtualBox). Multiple shutdown and restart attempts were performed using both GUI and command-line methods. The event does not appear in the Security log following any of these operations. This is a known behaviour caused by a race condition during the Windows shutdown sequence — the Event Log service terminates before the LSA can write 4609 to disk. This is well-documented across Windows Server versions and is not a lab misconfiguration. In production SOC environments, **Event 6006** from the System log is used as the reliable clean shutdown indicator. Event 4609 is documented here for completeness and theoretical understanding, but analysts should not depend on it being present.

---

## Audit Policy Setup

### Verify Current Status

```cmd
auditpol /get /subcategory:"Security State Change"
```

### Command Line

```cmd
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
```

### Group Policy (GUI)

1. Open **Group Policy Management** → right-click domain → **Edit**
2. Navigate to: `Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → System`
3. Double-click **Audit Security State Change** → check **Success** → OK
4. Run `gpupdate /force`

---

## Generating the Event

Event 4609 requires an actual system shutdown or restart. It cannot be triggered by any command while Windows is running normally.

### GUI Method

Start Menu → Power icon → **Shut Down** or **Restart**

### Command Line Method

```cmd
:: Shutdown with delay — gives LSA slightly more time to write 4609
shutdown /s /t 30

:: Restart with delay
shutdown /r /t 30
```

> The 30-second delay (`/t 30`) gives the LSA additional time to flush 4609 before the Event Log service stops. Even with this delay, 4609 may still not appear on Windows Server due to the race condition described above.

### PowerShell Method

```powershell
Restart-Computer -Force
```

---

## Detecting the Event

### GUI — Event Viewer

1. Open **Event Viewer** → **Windows Logs** → **Security**
2. Click **Filter Current Log**
3. Enter Event ID: `4609` → OK
4. If the event is present, it will appear with a timestamp just before the corresponding 4608

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Date and Time | Shutdown timestamp — should be just before the next 4608 boot time |
| Computer | Machine name |

### PowerShell — Detection Commands

```powershell
# Check if any 4609 events exist in the Security log
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4609
} -ErrorAction SilentlyContinue | Select-Object -First 5 | Format-List TimeCreated, Message
```

```powershell
# Compare 4608 and 4609 counts — gap indicates missing shutdown events
$boots     = (Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4608 } -ErrorAction SilentlyContinue).Count
$shutdowns = (Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4609 } -ErrorAction SilentlyContinue).Count

Write-Host "Boot events    (4608): $boots"
Write-Host "Shutdown events(4609): $shutdowns"

if ($boots -gt $shutdowns) {
    Write-Host ""
    Write-Host "NOTE: More boots than shutdowns recorded." -ForegroundColor Yellow
    Write-Host "This is expected on Windows Server due to 4609 race condition." -ForegroundColor Yellow
    Write-Host "Use Event 6006 in System log for reliable clean shutdown detection." -ForegroundColor Cyan
}
```

```powershell
# Recommended alternative — use 6006 instead of 4609 for clean shutdown detection
Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 6006
    StartTime = (Get-Date).AddDays(-7)
} | Select-Object TimeCreated | Format-Table -AutoSize
```

---

## SOC Analyst Notes

### 4609 vs 6006 — Which to Use

| | Event 4609 | Event 6006 |
|---|---|---|
| Log | Security | System |
| Reliability on Windows Server | Low — race condition | High — always fires |
| Written by | LSA | Event Log service |
| Fires during | LSA shutdown | Event Log service shutdown |
| Use in production | Reference only | Primary clean shutdown indicator |

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | 4609 present alongside 6006 — normal clean shutdown |
| 🟡 Medium | 4609 absent but 6006 present — likely race condition, not suspicious |
| 🔴 High | Neither 4609 nor 6006 present before next boot — possible forced kill |
| 🔴 Critical | No 4609 or 6006 but 6008 present — confirmed unexpected shutdown |

### MITRE ATT&CK Reference

- **T1529** — System Shutdown/Reboot
- **T1070** — Indicator Removal on Host
