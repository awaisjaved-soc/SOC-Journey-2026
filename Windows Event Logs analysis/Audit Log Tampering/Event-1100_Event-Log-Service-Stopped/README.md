# Event ID 1100 — Event Log Service Stopped

**Log:** Security  
**Category:** System  
**Subcategory:** Security State Change  
**Level:** Information  
**Lab Environment:** Windows Server 2022 — TECHCORP / techcorp.local  
**Lab Status:** ⚠️ Could Not Be Generated — See Lab Note Below

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 1100 |
| Event Name | The event logging service has shut down |
| Log Location | Windows Logs → Security |
| Audit Category | System |
| Default State | Always fires — no configuration needed |
| SACL Required | No |

---

## What Is Event 1100?

Event 1100 fires when the Windows Event Log service stops while the system is still running. This is critically different from Event 6006, which fires when the Event Log service stops during a normal, clean system shutdown. Event 1100 specifically captures the service being stopped mid-session — while Windows is active and a user is logged in.

When the Event Log service stops, all Windows logging ceases immediately. No Security events, no System events, no Application events. The machine continues running normally from the user's perspective, but the entire audit trail goes completely dark. An attacker who successfully stops the Event Log service can then perform any action — installing malware, creating backdoors, dumping credentials — with no log evidence being generated.

Event 1100 is the last thing written to any log before this total blackout occurs. In a SIEM environment, the absence of events from a host that was previously generating activity is itself an alertable condition — called a log silence detection. If a machine that normally sends 50 events per minute suddenly goes silent, that gap is suspicious regardless of whether 1100 was forwarded before the service stopped.

### Why This Is More Dangerous Than Log Clearing

Clearing the log (Event 1102) destroys past evidence. Stopping the Event Log service (Event 1100) prevents future evidence from being created. An attacker who combines both — first stops the service, does their malicious work, then restarts the service and clears the log — creates two blind spots: one for the future and one for the past.

---


## Lab Note — Why This Event Could Not Be Generated

> **Lab Note:** Event 1100 could not be generated in this lab environment (Windows Server 2022). Multiple methods were attempted — `services.msc` GUI, `net stop eventlog`, and `Stop-Service -Force` via PowerShell. All methods failed with **Error 1061: The service cannot accept control messages at this time**.
>
> This is intentional behaviour introduced by Microsoft in modern Windows versions. The Windows Event Log service is protected at the OS level specifically to prevent it from being easily stopped while the system is running. Windows recognises that an active session stopping the logging service is inherently suspicious, so it protects the service from standard stop commands.
>
> In real attacks, threat actors use advanced techniques to work around this protection — including suspending the `svchost.exe` process hosting the service using tools like Process Explorer or Mimikatz, or using kernel-level drivers to bypass the protection. These techniques are beyond the scope of this lab and would risk system instability.
>
> This limitation itself is useful SOC knowledge. The fact that modern Windows resists Event Log service termination means that if you DO see Event 1100 in production, the attacker had significant technical capability and likely used advanced tools to achieve it. The bar for generating this event is higher than most events in this category.

---

## Audit Policy Setup

No audit policy configuration is required. 1100 fires automatically when the service stops.

---

## Generating the Event

The following methods were attempted. They are documented here for completeness. On modern Windows Server 2022, all typically fail with Error 1061.

### GUI Method

1. Open **Services** (`services.msc`)
2. Find **Windows Event Log**
3. Right-click → **Stop**
4. Windows warns about dependent services — click **Yes**
5. On modern Windows Server 2022 this will fail with Error 1061

### Command Line Method

---

<img width="956" height="488" alt="Screenshot_1" src="https://github.com/user-attachments/assets/8bf3392e-0b54-44d5-870a-160eac6be0cf" />

---

```cmd
net stop eventlog
```

### PowerShell Method

```powershell
Stop-Service -Name EventLog -Force
```
---

<img width="857" height="418" alt="Screenshot_2" src="https://github.com/user-attachments/assets/d4c09400-cec3-4d9b-8ae5-640f3df3a48c" />

---

> All three methods fail on Windows Server 2022 with Error 1061. This is expected behaviour on modern Windows.

---

<img width="755" height="383" alt="Screenshot_3" src="https://github.com/user-attachments/assets/fafc2cb3-a71d-4691-bc18-5da903e53f0d" />

---


## Detecting the Event

Even though 1100 could not be generated in this lab, the detection methods are documented here for real-world application.

### GUI — Event Viewer

1. Event Viewer → Windows Logs → **Security**
2. Filter → Event ID: `1100`
3. Note the timestamp and then look at what events appear after the gap when logging resumed

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Date and Time | When logging stopped |
| Events after the gap | What was the first thing logged when service restarted |
| Duration of gap | How long was the system running without logging |

### PowerShell Detection

```powershell
# Search for Event Log service stop events
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 1100
} -ErrorAction SilentlyContinue | Select-Object -First 5 | Format-List TimeCreated, Message
```

```powershell
# Detect mid-session log stops — distinguish from normal shutdown 6006
$stopEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 1100
    StartTime = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue

foreach ($evt in $stopEvents) {
    $nearbyShutdown = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4609
        StartTime = $evt.TimeCreated.AddMinutes(-2)
        EndTime   = $evt.TimeCreated.AddMinutes(2)
    } -ErrorAction SilentlyContinue

    if (-not $nearbyShutdown) {
        Write-Host "=== SUSPICIOUS: Event Log stopped mid-session ===" -ForegroundColor Red
        Write-Host "Time: $($evt.TimeCreated)"
        Write-Host "No shutdown event nearby — this was NOT a normal shutdown."
    }
}
```

---

<img width="954" height="486" alt="Screenshot_5" src="https://github.com/user-attachments/assets/ec10482e-5d81-463f-a7ae-1736550986a4" />

---

## SOC Analyst Notes

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | 1100 during a confirmed clean shutdown — paired with 4609 and 6006 |
| 🔴 Critical | 1100 mid-session with no associated shutdown event |
| 🔴 Critical | 1100 followed by suspicious activity when logging resumes |

### MITRE ATT&CK Reference

- **T1562.002** — Impair Defenses: Disable Windows Event Logging
