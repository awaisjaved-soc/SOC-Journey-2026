# Event ID 4608 — Windows Is Starting Up

**Log:** Security  
**Category:** System  
**Subcategory:** Security State Change  
**Level:** Information  
**Lab Environment:** Windows Server 2019 — TECHCORP / techcorp.local

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 4608 |
| Event Name | Windows is starting up |
| Log Location | Windows Logs → Security |
| Audit Category | System |
| Audit Subcategory | Security State Change |
| Default State | Enabled by default on most Windows systems |
| SACL Required | No — fires automatically during boot |

---

## What Is Event 4608?

Event 4608 is the very first Security event written after every Windows boot. It fires the moment the Local Security Authority (LSA) initialises during the startup sequence — before any user logs in, before any services run, before any other Security event can be generated. Because of this, it serves as the **boot timestamp anchor** for the entire Security log.

The event itself contains almost no data beyond the timestamp and the machine name. There are no user fields, no process fields, no additional details. Its entire forensic value is the timestamp — it tells you precisely when a Windows session began.

In SOC work, 4608 is used primarily for **timeline construction**. When investigating an incident, analysts locate the 4608 events in the Security log to divide the log into distinct boot sessions. Every event between one 4608 and the next belongs to a single session. This allows you to ask questions like: which session did the suspicious activity occur in, how long was that session, and was there anything unusual about when the machine booted?

---

## What Happens When This Event Fires

During the Windows boot process, the kernel loads first, then device drivers, then system services. When the LSA (the component responsible for all authentication and security policy enforcement) finishes initialising, it writes Event 4608 to the Security log as a self-announcement. From this point forward, the Security log is active and all subsequent audit events will be recorded.

Nothing appears on screen when 4608 fires. The machine is still in the process of booting. You will not see any visual indicator. The evidence is written silently to the Security log and waits for you to read it in Event Viewer.

---

## Audit Policy Setup

### Verify Current Status

```cmd
auditpol /get /subcategory:"Security State Change"
```

This is typically already enabled. If the output shows `No Auditing`, enable it:

### Command Line

```cmd
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
```

### Group Policy (GUI)

1. Open **Group Policy Management** → right-click domain → **Edit**
2. Navigate to: `Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → System`
3. Double-click **Audit Security State Change**
4. Check **Configure the following audit events** → check **Success** → OK
5. Run `gpupdate /force`

---

## Generating the Event

There is only one way to generate Event 4608 — **reboot or start the machine**. It cannot be triggered by any command while Windows is already running.

### GUI Method

Start Menu → Power icon → **Restart**

### Command Line Method

```cmd
shutdown /r /t 0
```

### PowerShell Method

```powershell
Restart-Computer -Force
```

After the VM restarts and you log back in, Event 4608 will be in the Security log with the exact boot timestamp.

> **Lab tip:** A restart generates both 4609 (shutdown) and 4608 (startup) in a single cycle, giving you two events from one action.

---

## Detecting the Event

### GUI — Event Viewer

1. Open **Event Viewer** → **Windows Logs** → **Security**
2. Click **Filter Current Log** in the right panel
3. Enter Event ID: `4608` → OK
4. The most recent entry at the top is from your last boot
5. Note the timestamp — this is your current session start time

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Date and Time | The exact boot timestamp — this is the primary value |
| Computer | Machine name — confirms which system booted |
| Keywords | Audit Success |

### PowerShell — Detection Commands

```powershell
# Show the 5 most recent boot events
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4608
} | Select-Object -First 5 | Format-List TimeCreated, Message
```

```powershell
# All boots in the last 30 days — useful for uptime and reboot history
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4608
    StartTime = (Get-Date).AddDays(-30)
} | Select-Object TimeCreated | Format-Table -AutoSize
```

```powershell
# Detect off-hours boots — reboots outside 7AM–7PM are suspicious on servers
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4608
    StartTime = (Get-Date).AddDays(-30)
} | Where-Object {
    $_.TimeCreated.Hour -lt 7 -or $_.TimeCreated.Hour -gt 19
} | ForEach-Object {
    Write-Host "=== OFF-HOURS BOOT DETECTED ===" -ForegroundColor Red
    Write-Host "Time : $($_.TimeCreated)"
    Write-Host "Day  : $($_.TimeCreated.DayOfWeek)"
    Write-Host ""
}
```

```powershell
# Build a full boot timeline — pair with 4609 for session mapping
$boots = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4608
    StartTime = (Get-Date).AddDays(-14)
} | Select-Object TimeCreated

Write-Host "=== Boot Timeline (Last 14 Days) ===" -ForegroundColor Cyan
$boots | Format-Table -AutoSize
Write-Host "Total boots: $($boots.Count)"
```

---

## SOC Analyst Notes

### What 4608 Tells You

- The exact moment a Windows session began
- How many times a machine has rebooted in a given period
- Whether reboots are happening at unusual hours
- The starting point for correlating all other Security events in that session

### What 4608 Does NOT Tell You

- Why the machine booted (normal start, reboot after update, attacker-forced reboot)
- Whether the previous shutdown was clean or unexpected
- Who initiated the reboot

For those answers, correlate with 4609 (previous session end), 6005 (System log reboot marker), and 6008 (unexpected shutdown record).

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Boot during business hours, expected maintenance window |
| 🟡 Medium | Unscheduled reboot during business hours |
| 🔴 High | Boot at 3 AM with no change management ticket |
| 🔴 Critical | Multiple rapid boots in short succession — attacker applying persistence or evading memory forensics |

### MITRE ATT&CK Reference

- **T1529** — System Shutdown/Reboot (attacker-initiated reboot to apply persistence)
- **T1070** — Indicator Removal (reboot to clear in-memory artifacts)
