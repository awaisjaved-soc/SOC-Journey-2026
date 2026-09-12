# Event ID 6008 — Previous Unexpected Shutdown

**Log:** System  
**Category:** System  
**Subcategory:** N/A — written automatically by the Event Log service  
**Level:** Error  
**Lab Environment:** Windows Server 2019 — TECHCORP / techcorp.local

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 6008 |
| Event Name | The previous system shutdown was unexpected |
| Log Location | Windows Logs → **System** (not Security) |
| Source | EventLog |
| Level | **Error** — the only Error-level event in this category |
| Default State | Always active — no configuration needed |
| SACL Required | No |
| Audit Policy Required | No |
| When It Fires | During the **next boot** after an unclean shutdown |

---

## What Is Event 6008?

Event 6008 is the most forensically interesting event in the System Lifecycle category. Unlike every other event in this tier which fires during the event it describes, Event 6008 fires **on the next boot** — it is Windows retrospectively reporting that something went wrong with the previous session.

When Windows starts up, one of the first things the Event Log service does is check whether the previous session ended cleanly. It does this by looking for Event 6006 (Event Log service stopped cleanly). If 6006 is absent — meaning the Event Log service never got to write its shutdown entry — Windows concludes the previous shutdown was unexpected and writes Event 6008 to record this.

The event contains the **date and time of the unexpected shutdown** — meaning it tells you exactly when the previous session ended abnormally, not just that it happened. This timestamp is recorded from the last successful write to the System log before the crash or kill, giving investigators a precise point in time to anchor their investigation.

---

## What Causes Event 6008

Event 6008 is generated after any shutdown that does not go through the normal Windows shutdown sequence:

**Power loss** — the physical machine or VM lost power without warning. The system had no opportunity to run any shutdown procedures.

**Blue Screen of Death (BSOD)** — the Windows kernel encountered an unrecoverable error and crashed. The Event Log service was terminated by the crash without writing 6006.

**Hypervisor force-stop** — in a virtualised environment, selecting "Power Off" in VirtualBox, VMware, or Hyper-V immediately terminates the VM process at the host level. From Windows' perspective this is identical to a power cut.

**Hardware failure** — overheating, RAM failure, or CPU issues can cause an immediate system halt with no shutdown sequence.

**Attacker-initiated forced reboot** — attackers sometimes force an immediate reboot using low-level tools to clear in-memory artefacts, apply persistence that requires a reboot, or disrupt logging. A forced reboot that bypasses the normal shutdown sequence leaves a 6008 on the next boot.

**Kill signal to critical process** — if a process like `wininit.exe` or `smss.exe` is forcibly terminated, Windows may crash immediately without a clean shutdown.

---

## Why 6008 Matters in SOC Work

In a server environment, systems are expected to run continuously for months or years. A 6008 on a production server that has no associated change management ticket — no scheduled maintenance, no planned reboot, no known power event — is always a priority investigation item.

The attack scenario is specific: an attacker who has achieved code execution on a system may force a reboot to apply a persistence mechanism that requires restart (like a registry Run key they just wrote), or to clear memory that might contain forensic evidence of their tools. The forced reboot leaves a 6008. Combined with the suspicious events from the session before the reboot — registry modifications, new services, unusual process activity — the 6008 helps complete the attack timeline.

The timestamp inside 6008 is particularly valuable. It tells you when the previous session ended. You can then go back through the logs from that session and look at everything that happened in the final minutes before the unexpected shutdown.

---

## Generating the Event

Event 6008 requires a **forced, ungraceful shutdown**. The machine must not go through its normal shutdown sequence. After the forced kill, you must boot the machine back up — 6008 appears on the next boot, not immediately.

### Method 1 — VirtualBox Power Off (Recommended for Lab)

This is the most reliable method and exactly simulates a power cut:

1. While the Windows Server VM is running normally
2. In the VirtualBox menu bar → **Machine** → **Close**
3. Select **Power Off the machine** → click **Power Off**
4. Wait for the VM to stop completely
5. Start the VM again from VirtualBox
6. After Windows boots and you log in → Event 6008 will be in the System log

---

<img width="498" height="328" alt="Screenshot_5" src="https://github.com/user-attachments/assets/f0c495ce-8ece-4014-bd73-d92b88946234" />

---


### Method 2 — Command Line Forced Shutdown

```cmd
:: Force immediate shutdown with no graceful sequence
shutdown /r /f /t 0
```

The `/f` flag forces all running applications to close immediately without saving. This is more abrupt than a normal restart but Windows may still partially process the shutdown sequence depending on timing — VirtualBox Power Off is more reliable for guaranteeing 6008.

### Method 3 — PowerShell

```powershell
# Force stop — less reliable than VirtualBox Power Off for generating 6008
Stop-Computer -Force
```

---

<img width="470" height="330" alt="Screenshot_2" src="https://github.com/user-attachments/assets/a0d7ba14-07f2-4abf-8f7c-b7769f37963a" />

---


## Detecting the Event

### GUI — Event Viewer

1. Boot the VM after the forced shutdown
2. Open **Event Viewer** → **Windows Logs** → **System**
3. Click **Filter Current Log**
4. Enter Event ID: `6008` → OK
5. Source column shows `EventLog`
6. Level column shows **Error** — the only error-level event in this category
7. Read the event message — it contains the date and time of the unexpected shutdown

**Event message will read something like:**
> The previous system shutdown at 14:23:07 on 3/09/2026 was unexpected.

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Date and Time | When 6008 was written — i.e. the current boot time |
| Level | Error — distinguishes it from normal lifecycle events |
| Message | Contains the timestamp of the unexpected shutdown |
| Source | EventLog |

---

<img width="645" height="435" alt="Screenshot_1" src="https://github.com/user-attachments/assets/ef443e6d-4adf-49cf-8717-7d26d2712284" />

---


### PowerShell — Detection Commands

```powershell
# Find all unexpected shutdown records
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Id      = 6008
} | Select-Object -First 5 | Format-List TimeCreated, Message
```

```powershell
# Extract the unexpected shutdown timestamp from the message
Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 6008
    StartTime = (Get-Date).AddDays(-30)
} | ForEach-Object {
    Write-Host "=== UNEXPECTED SHUTDOWN RECORDED ===" -ForegroundColor Red
    Write-Host "6008 Written At (boot time) : $($_.TimeCreated)"
    Write-Host "Event Message              : $($_.Message)"
    Write-Host ""
}
```
---

<img width="674" height="385" alt="Screenshot_3" src="https://github.com/user-attachments/assets/be0b9c8e-1347-4475-a791-03ced84a54f5" />

---


```powershell
# Full system lifecycle report — all five events together
Write-Host "=== SYSTEM LIFECYCLE REPORT ===" -ForegroundColor Cyan
Write-Host ""

Write-Host "--- Security Log Boots (4608) ---" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4608; StartTime=(Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue | Select-Object TimeCreated | Format-Table -AutoSize

Write-Host "--- Security Log Shutdowns (4609) ---" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4609; StartTime=(Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue | Select-Object TimeCreated | Format-Table -AutoSize

Write-Host "--- System Log Service Start / Reboot (6005) ---" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{
    LogName='System'; Id=6005; StartTime=(Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue | Select-Object TimeCreated | Format-Table -AutoSize

Write-Host "--- System Log Clean Shutdown (6006) ---" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{
    LogName='System'; Id=6006; StartTime=(Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue | Select-Object TimeCreated | Format-Table -AutoSize

Write-Host "--- System Log Unexpected Shutdown (6008) ---" -ForegroundColor Red
Get-WinEvent -FilterHashtable @{
    LogName='System'; Id=6008; StartTime=(Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Format-List
```

```powershell
# Hunt for 6008 events that correlate with suspicious pre-shutdown activity
# First get the unexpected shutdown timestamps
$unexpected = Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 6008
    StartTime = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue

foreach ($evt in $unexpected) {
    Write-Host "Unexpected shutdown detected. Checking Security log for suspicious activity before this shutdown..." -ForegroundColor Yellow

    # Look for suspicious events in the 30 minutes before the unexpected shutdown
    $suspiciousEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = @(4657, 4698, 4697, 7045)
        StartTime = $evt.TimeCreated.AddMinutes(-30)
        EndTime   = $evt.TimeCreated
    } -ErrorAction SilentlyContinue

    if ($suspiciousEvents) {
        Write-Host "=== SUSPICIOUS PRE-SHUTDOWN ACTIVITY FOUND ===" -ForegroundColor Red
        $suspiciousEvents | Select-Object TimeCreated, Id, Message | Format-List
    } else {
        Write-Host "No high-priority events found in the 30 minutes before this shutdown." -ForegroundColor Green
    }
}
```

---

## SOC Analyst Notes

### Investigation Workflow When 6008 Is Found

```
Step 1: Note the timestamp inside the 6008 message — this is when the crash/kill happened
Step 2: Go back to the Security log and System log for that session
Step 3: Review all events in the 30-60 minutes BEFORE the unexpected shutdown time
Step 4: Look specifically for: 4657 (registry modified), 4698 (task created),
        7045 (service installed), 4688 (unusual processes), 4616 (time changed)
Step 5: Check if there is a 6008 pattern — is this the first one or are there many?
Step 6: Correlate with change management — was a reboot planned?
```

### Normal vs Suspicious 6008

| Scenario | Verdict |
|---|---|
| 6008 after a known power outage | Normal — document and close |
| 6008 on a workstation with no attached UPS | Normal — power events happen |
| 6008 on a production server with no change ticket | **Investigate immediately** |
| 6008 preceded by suspicious registry or service events | **High priority incident** |
| Multiple 6008 events in a short period | **Critical — attacker may be force-rebooting** |

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Single 6008 on workstation, known power event |
| 🟡 Medium | 6008 on server, no immediate explanation |
| 🔴 High | 6008 on server preceded by unusual Security log activity |
| 🔴 Critical | Multiple 6008 events in rapid succession, or 6008 after confirmed attacker activity |

### MITRE ATT&CK Reference

- **T1529** — System Shutdown/Reboot (attacker forcing reboot)
- **T1070** — Indicator Removal on Host (reboot to clear memory artefacts)
- **T1485** — Data Destruction (forced shutdown to corrupt running processes)
