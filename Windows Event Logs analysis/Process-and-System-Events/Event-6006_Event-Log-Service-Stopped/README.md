# Event ID 6006 — Event Log Service Stopped (Clean Shutdown)

**Log:** System  
**Category:** System  
**Subcategory:** N/A — written automatically by the Event Log service  
**Level:** Information  
**Lab Environment:** Windows Server 2019 — TECHCORP / techcorp.local

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 6006 |
| Event Name | The Event log service was stopped |
| Log Location | Windows Logs → **System** (not Security) |
| Source | EventLog |
| Default State | Always active — no configuration needed |
| SACL Required | No |
| Audit Policy Required | No |

---

## What Is Event 6006?

Event 6006 is the last event written to the System log before a clean shutdown completes. It fires when the Windows Event Log service stops as part of the normal shutdown sequence — and because the Event Log service writes this entry itself just before terminating, it is one of the most reliable shutdown indicators in the entire Windows event logging system.

The key word is **clean**. Event 6006 only fires when Windows goes through its proper, graceful shutdown procedure — stopping services in order, flushing write buffers, and cleanly terminating all components. If the machine loses power, crashes, is forcibly killed through the hypervisor, or experiences a kernel panic, the Event Log service never gets to write 6006. Its absence after a reboot is therefore meaningful evidence.

Event 6006 pairs with Event 6005 to form the System log's session bookends. Every Windows session in the System log should look like this:

```
6005  →  machine came online
         [session activity]
6006  →  machine shut down cleanly
6005  →  machine came online again
```

When you see a 6005 without a preceding 6006, the previous session ended abnormally. That missing 6006 is confirmed by Event 6008 on the next boot.

---

## 6006 as the Reliable Alternative to 4609

Event 4609 in the Security log is designed to mark the end of a Windows session but is notoriously unreliable on Windows Server due to a race condition — the Event Log service often stops before LSA can write 4609. Event 6006 does not have this problem because it is written by the Event Log service itself as its final action. The service cannot stop without writing 6006, because writing 6006 is part of the stop sequence.

This makes 6006 the **production-grade clean shutdown indicator** that SOC teams actually rely on, while 4609 remains theoretical on server builds.

---

## What Happens When This Event Fires

During a clean shutdown, Windows stops services in reverse dependency order. Services that depend on the Event Log service are stopped first. Once all dependent services have stopped, the Event Log service itself begins its shutdown. Before closing the log files and terminating, it writes Event 6006 as its final log entry. After 6006 is written, the log files are closed and no further events can be recorded until the next boot brings the service back up with Event 6005.

Nothing appears on screen when 6006 fires — the machine is in the process of shutting down and the screen will go dark shortly after.

---

## Audit Policy Setup

**No audit policy configuration is required.** Event 6006 is written by the Event Log service as part of its own stop routine. It fires automatically during every clean shutdown regardless of audit policy settings.

---

## Generating the Event

Event 6006 requires an actual clean system shutdown or restart. It cannot be triggered by any command while Windows is running. Forced shutdowns (pulling power, VirtualBox Power Off, killing the VM) will NOT generate 6006.

### GUI Method

Start Menu → Power icon → **Shut Down** or **Restart**

Both produce 6006. Restart also produces a 6005 immediately after on the next boot.

### Command Line Method

```cmd
:: Clean shutdown
shutdown /s /t 0

:: Clean restart — generates 6006 (shutdown) then 6005 (startup)
shutdown /r /t 0
```
---

<img width="634" height="434" alt="Screenshot_4" src="https://github.com/user-attachments/assets/324887b4-d140-4fe9-a8b0-719142ac1dfd" />

---


### PowerShell Method

```powershell
# Clean restart — best for lab as machine comes back automatically
Restart-Computer -Force
```

After the machine boots back up, open Event Viewer → System log → filter for 6006. The entry from your shutdown will be there.

---

<img width="635" height="437" alt="Screenshot_2" src="https://github.com/user-attachments/assets/1e82b763-83f2-4c0a-be52-f921d6900af4" />

---


## Detecting the Event

### GUI — Event Viewer

1. Open **Event Viewer** → **Windows Logs** → **System**
2. Click **Filter Current Log**
3. Enter Event ID: `6006` → OK
4. Source column shows `EventLog`
5. Each entry represents one clean shutdown or restart
6. Correlate timestamp with the 6005 that follows it to calculate session length

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Date and Time | Shutdown timestamp |
| Source | EventLog |
| Computer | Machine name |

---

<img width="644" height="182" alt="Screenshot_1" src="https://github.com/user-attachments/assets/b04782c5-05ba-4ad9-8f33-75770b9be448" />

---


### PowerShell — Detection Commands

```powershell
# Recent clean shutdowns
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Id      = 6006
} | Select-Object -First 5 | Format-List TimeCreated, Message
```

```powershell
# Compare 6005 and 6006 counts — gap reveals unclean shutdowns
$starts = (Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 6005
    StartTime = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue).Count

$stops = (Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 6006
    StartTime = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue).Count

Write-Host "Clean shutdowns / restarts (6006) : $stops"
Write-Host "Boots / restarts           (6005) : $starts"

if ($starts -gt $stops) {
    $diff = $starts - $stops
    Write-Host ""
    Write-Host "WARNING: $diff boot(s) without a preceding clean shutdown." -ForegroundColor Red
    Write-Host "Check for Event 6008 to confirm unexpected shutdowns." -ForegroundColor Yellow
}
```
---

<img width="959" height="399" alt="Screenshot_3" src="https://github.com/user-attachments/assets/17eaa26a-c782-4bb4-a8a4-e58519564de7" />

---


```powershell
# Calculate session length between 6006 and its preceding 6005
$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = @(6005, 6006)
    StartTime = (Get-Date).AddDays(-14)
} | Sort-Object TimeCreated

$sessionStart = $null
foreach ($evt in $events) {
    if ($evt.Id -eq 6005) {
        $sessionStart = $evt.TimeCreated
    } elseif ($evt.Id -eq 6006 -and $sessionStart) {
        $duration = $evt.TimeCreated - $sessionStart
        [PSCustomObject]@{
            SessionStart = $sessionStart
            SessionEnd   = $evt.TimeCreated
            Uptime       = "$([int]$duration.TotalHours)h $($duration.Minutes)m"
            CleanShutdown = "Yes"
        }
        $sessionStart = $null
    }
} | Format-Table -AutoSize
```

---

## SOC Analyst Notes

### The 6005/6006 Session Model

Every Windows system should show a clean alternating pattern in the System log:

```
6005 → 6006 → 6005 → 6006 → 6005 → 6006
```

Any break in this pattern — a 6005 not preceded by a 6006 — means the previous session ended without a clean shutdown. In a server environment this is always worth investigating.

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | 6006 present before every 6005 — all sessions ended cleanly |
| 🟡 Medium | Occasional missing 6006 — may be legitimate power event |
| 🔴 High | Missing 6006 on a server that should have 24/7 uptime |
| 🔴 Critical | Pattern of missing 6006 events — repeated forced kills, possible attacker activity |

### MITRE ATT&CK Reference

- **T1529** — System Shutdown/Reboot
- **T1070** — Indicator Removal on Host
