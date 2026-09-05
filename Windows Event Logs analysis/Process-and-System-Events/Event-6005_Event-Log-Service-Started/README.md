# Event ID 6005 — Event Log Service Started (System Reboot)

**Log:** System  
**Category:** System  
**Subcategory:** N/A — written automatically by the Event Log service  
**Level:** Information  
**Lab Environment:** Windows Server 2019 — TECHCORP / techcorp.local

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 6005 |
| Event Name | The Event log service was started |
| Log Location | Windows Logs → **System** (not Security) |
| Source | EventLog |
| Default State | Always active — no configuration needed |
| SACL Required | No |
| Audit Policy Required | No |

---

## What Is Event 6005?

Event 6005 fires in the System log every time the Windows Event Log service starts — which happens as part of every boot sequence. It is universally treated by SOC analysts and incident responders as the definitive **"machine came online"** marker.

The distinction between 6005 and 4608 is important. Event 4608 fires in the **Security log** when the LSA initialises. Event 6005 fires in the **System log** when the Event Log service itself starts. Both happen during the same boot, but they live in different logs and serve slightly different purposes.

In practice, 6005 is the more commonly referenced reboot indicator for two reasons. First, it lives in the System log, which is sometimes preserved even when attackers have cleared the Security log — giving investigators a backup boot timeline. Second, 6005 pairs naturally with 6006 (Event Log service stopped) to form the System log's session bookends, making the 6005/6006 pair the System log equivalent of the Security log's 4608/4609 pair.

The timestamp of 6005 tells you exactly when the machine came online. The gap between consecutive 6005 events tells you how long the machine ran between reboots. A server that should have months of uptime showing a 6005 at 3 AM is immediately worth investigating.

---

## What Happens When This Event Fires

Early in the boot sequence, after the kernel and core drivers load, Windows starts its system services. The Event Log service is one of the first services to start because most other services depend on it for logging. The moment the Event Log service initialises and opens the log files for writing, it records Event 6005 as its startup announcement.

From this point forward, any service or application that needs to write to the Windows event logs can do so. Event 4608 typically fires shortly after 6005, as the LSA initialises next and announces itself to the Security log.

Nothing appears on screen when 6005 fires. The machine is still booting. The event is written silently and becomes readable in Event Viewer once the desktop loads.

---

## Audit Policy Setup

**No audit policy configuration is required.** Event 6005 is written by the Event Log service itself as part of its own startup routine. It fires automatically on every boot regardless of any audit policy settings. You cannot disable it through normal audit policy changes.

There is nothing to configure. If you can open the System log in Event Viewer, you already have 6005 events.

---

## Generating the Event

Event 6005 fires on every boot. The only way to generate it is to reboot or start the machine.

### GUI Method

Start Menu → Power icon → **Restart**

### Command Line Method

```cmd
shutdown /r /t 0
```
---

<img width="797" height="436" alt="Screenshot_1" src="https://github.com/user-attachments/assets/3206caf0-f26d-43c4-bb31-b3cb00021491" />

---


### PowerShell Method

```powershell
Restart-Computer -Force
```

After logging back in, open Event Viewer → System log → filter for 6005. The most recent entry will be from the boot you just performed.

---

<img width="638" height="164" alt="Screenshot_3" src="https://github.com/user-attachments/assets/897c8606-b822-42f1-9768-610e24f28788" />

---


## Detecting the Event

### GUI — Event Viewer

1. Open **Event Viewer** → **Windows Logs** → **System**
2. Click **Filter Current Log**
3. Enter Event ID: `6005` → OK
4. Source column will show `EventLog`
5. Each entry represents one boot or restart
6. The most recent is your current session start

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Date and Time | Exact boot timestamp |
| Source | EventLog — confirms this is the genuine service start event |
| Computer | Machine name |
| Level | Information |

### PowerShell — Detection Commands

```powershell
# Most recent boot events
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Id      = 6005
} | Select-Object -First 5 | Format-List TimeCreated, Message
```

```powershell
# All reboots in the last 30 days with day of week
Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 6005
    StartTime = (Get-Date).AddDays(-30)
} | ForEach-Object {
    [PSCustomObject]@{
        BootTime   = $_.TimeCreated
        DayOfWeek  = $_.TimeCreated.DayOfWeek
        Hour       = $_.TimeCreated.Hour
    }
} | Format-Table -AutoSize
```
---

<img width="757" height="432" alt="Screenshot_2" src="https://github.com/user-attachments/assets/cb8dee5d-3cc1-43f7-a22a-6eec2a4eb081" />


---


```powershell
# Off-hours reboot detection — flag boots outside 7AM-7PM
Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 6005
    StartTime = (Get-Date).AddDays(-30)
} | Where-Object {
    $_.TimeCreated.Hour -lt 7 -or $_.TimeCreated.Hour -gt 19
} | ForEach-Object {
    Write-Host "=== OFF-HOURS REBOOT DETECTED ===" -ForegroundColor Red
    Write-Host "Time     : $($_.TimeCreated)"
    Write-Host "Day      : $($_.TimeCreated.DayOfWeek)"
    Write-Host ""
}
```

```powershell
# Count reboots per day — spike detection
Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 6005
    StartTime = (Get-Date).AddDays(-30)
} | Group-Object { $_.TimeCreated.Date.ToString("yyyy-MM-dd") } |
    Select-Object Name, Count |
    Sort-Object Name |
    Format-Table -AutoSize
```

```powershell
# Full reboot history with uptime calculation between boots
$boots = Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 6005
    StartTime = (Get-Date).AddDays(-30)
} | Select-Object TimeCreated | Sort-Object TimeCreated

for ($i = 1; $i -lt $boots.Count; $i++) {
    $uptime = $boots[$i].TimeCreated - $boots[$i-1].TimeCreated
    [PSCustomObject]@{
        BootTime        = $boots[$i].TimeCreated
        UptimeSinceLast = "$([int]$uptime.TotalHours)h $($uptime.Minutes)m"
    }
} | Format-Table -AutoSize
```

---

## SOC Analyst Notes

### 6005 vs 4608 — Understanding Both

| | Event 6005 | Event 4608 |
|---|---|---|
| Log | System | Security |
| Written by | Event Log service | LSA |
| Always present | Yes | Yes (if audit enabled) |
| Survives Security log wipe | Yes | No |
| Used for | System log session timeline | Security log session timeline |

In an incident where the Security log has been cleared, 6005 gives you the reboot timeline from the System log, letting you still build a session-based timeline for your investigation.

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Boot during business hours, expected |
| 🟡 Medium | Unscheduled reboot, no change ticket |
| 🔴 High | Off-hours boot on a production server |
| 🔴 Critical | Multiple 6005 events in rapid succession — attacker rebooting repeatedly |

### MITRE ATT&CK Reference

- **T1529** — System Shutdown/Reboot
- **T1070.001** — Indicator Removal: Clear Windows Event Logs (6005 survives this)
