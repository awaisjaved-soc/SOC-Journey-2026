# Event ID 1102 — Audit Log Cleared

**Log:** Security  
**Category:** System  
**Subcategory:** Security State Change  
**Level:** Information  
**Lab Environment:** Windows Server 2022 — TECHCORP / techcorp.local  
**Lab Status:** ✅ Successfully Generated

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 1102 |
| Event Name | The audit log was cleared |
| Log Location | Windows Logs → Security |
| Audit Category | System |
| Default State | Always fires — no configuration needed |
| SACL Required | No |

---

## What Is Event 1102?

Event 1102 is the single most important event in the entire Audit and Log Tampering category. It fires the moment someone clears the Windows Security event log — and it is the last event written to that log before all previous entries are permanently destroyed.

What makes 1102 uniquely significant is that it is self-referential. When an attacker clears the Security log to destroy evidence of their activity, Windows automatically writes Event 1102 documenting that the log was cleared, who cleared it, and exactly when it happened. The attacker destroys every previous log entry but cannot avoid leaving this one record of the destruction itself.

In real SOC environments, Event 1102 triggers an immediate escalation with no exceptions. There is no legitimate reason for a standard user or even most administrators to clear the Security log outside of a documented, pre-approved maintenance procedure. An unexpected 1102 at 3 AM from a user account that should not be doing maintenance is a confirmed incident in progress.

### The Real Attack Story Behind 1102

Understanding why attackers clear logs helps you understand the severity of this event. The sequence almost always looks like this:

An attacker gains initial access through phishing or exploitation. They escalate privileges to Administrator or SYSTEM. They perform their actual objectives — credential theft, data exfiltration, installing backdoors, creating persistence through scheduled tasks or WMI subscriptions. All of these actions generate Security log entries — 4688, 4697, 4698, 5861, and dozens more. The attacker knows that these logs document their entire operation.

Before leaving, they run a single command:
```
wevtutil cl Security
```

Everything is gone. Except for 1102.

### What 1102 Does NOT Tell You

Event 1102 tells you that the log was cleared, who cleared it, and when. It does not tell you what was in the log before it was cleared. That information is permanently gone from the local machine.

This is why SIEM log forwarding is so critical in real environments. If logs are shipped off the machine in real time to a SIEM like Splunk or Wazuh, clearing the local log does not destroy the SIEM copy. The attacker thinks they erased their tracks — but the SOC team has everything.

---

## Audit Policy Setup

Event 1102 fires automatically when the Security log is cleared. No additional audit policy configuration is required.

```cmd
auditpol /get /subcategory:"Security State Change"
```

---

## Generating the Event

> ⚠️ This permanently deletes all entries in the Security event log. Take screenshots of any important events before running this.

### GUI Method

1. Open **Event Viewer**
2. Click **Windows Logs** → **Security**
3. In the right panel click **Clear Log**
4. Dialog appears asking to save first — click **Clear** without saving
5. Event 1102 is immediately written as the first new entry in the now-empty log

### Command Line Method

```cmd
wevtutil cl Security
```

### PowerShell Method

```powershell
# Clear the Security log — generates Event 1102 immediately
Clear-EventLog -LogName Security

Write-Host "Security log cleared. Event 1102 written." -ForegroundColor Red
Write-Host "1102 should now be the first entry in the Security log." -ForegroundColor Yellow
```

---

## Detecting the Event

### GUI — Event Viewer

1. Open **Event Viewer** → **Windows Logs** → **Security**
2. After clearing, 1102 is the first and only entry at the top
3. Or filter → Event ID: `1102` → OK
4. Double-click to see who cleared it and when

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Subject: Account Name | Who cleared the log — never should be a standard user |
| Subject: Logon ID | Links to logon event — find how this account got in |
| Date and Time | When it was cleared — correlate with other suspicious activity |

### PowerShell Detection

```powershell
# Find all log clearing events
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 1102
} | Select-Object -First 5 | Format-List TimeCreated, Message
```

```powershell
# Immediate escalation alert for any log clearing
$clearEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 1102
    StartTime = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue

if ($clearEvents) {
    Write-Host "=== CRITICAL: SECURITY LOG CLEARING DETECTED ===" -ForegroundColor Red
    $clearEvents | ForEach-Object {
        Write-Host "Time    : $($_.TimeCreated)" -ForegroundColor Red
        Write-Host "Message : $($_.Message)" -ForegroundColor Red
        Write-Host ""
    }
} else {
    Write-Host "No log clearing events found." -ForegroundColor Green
}
```

---

## SOC Analyst Notes

### Investigation Workflow When 1102 Is Found

```
Step 1: Note the exact timestamp and account name from 1102
Step 2: Check SIEM — do you have logs from before the clearing?
Step 3: Look at the account that cleared the log
        → How did it authenticate? (Check 4624)
        → Is this account supposed to have admin rights?
Step 4: Check the System log — it is not cleared by this action
        Look for 6005/6006 (reboot events) and service events near the same time
Step 5: Escalate immediately — treat this as confirmed compromise until proven otherwise
```

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Known maintenance account, documented procedure, business hours |
| 🔴 Critical | Any unexpected account, outside business hours, no change ticket |
| 🔴 Critical | Immediately after other suspicious events (new service, WMI subscription) |

### MITRE ATT&CK Reference

- **T1070.001** — Indicator Removal: Clear Windows Event Logs
