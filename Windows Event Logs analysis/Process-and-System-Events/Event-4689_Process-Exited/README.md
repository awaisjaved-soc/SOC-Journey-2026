# Event 4689 – A Process Has Exited

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4689 |
| **Category** | Process & System Events |
| **Log** | Security |
| **Tier** | 🔴 Tier 1 – Critical |
| **SOC Importance** | 🟡 Medium (always pair with 4688) |

## What Is This Event?

Event 4689 is logged when a **process terminates**. On its own it is not very useful, but when paired with Event 4688 (Process Created), it tells you exactly how long a process ran — which is a key forensic data point.

**Short-lived processes** — those that start and exit within seconds — are a common malware pattern. Malware will often execute, do its job, and immediately exit to reduce its footprint and avoid detection.

---

## Setup – Must Do First

Event 4689 requires its own separate audit policy. Run this as **Administrator**:

```powershell
# Enable Process Termination Auditing
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
gpupdate /force
```

### Verify the Policy is Active

```powershell
auditpol /get /subcategory:"Process Termination"
```

Expected output: `Process Termination   Success and Failure`

> **Important:** If you only enabled "Process Creation" for Event 4688, Event 4689 will still NOT appear. They are separate audit subcategories and both must be enabled.

---

## How to Generate This Event

### Method 1 – Manual GUI
1. Open **Notepad** or **Calculator**
2. Close the program (click the X)
3. Event 4689 is generated

### Method 2 – PowerShell (Recommended for Lab)
```powershell
# Start Notepad and then stop it after 4 seconds
$proc = Start-Process notepad.exe -PassThru
Start-Sleep -Seconds 4
Stop-Process -Id $proc.Id -Force
```

> Using `-PassThru` captures the process object so you can stop it by ID. This is cleaner than hunting for the process manually.

---

## Detection Commands

### Basic Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4689} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        ProcessName = ($xml.Event.EventData.Data | Where {$_.Name -eq 'ProcessName'}).'#text'
        ProcessId   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'ProcessId'}).'#text'
        User        = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
    }
} | Format-Table -AutoSize
```

### Extended Detection – More Results
```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4689
} -MaxEvents 10 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        ProcessName = ($xml.Event.EventData.Data | Where {$_.Name -eq 'ProcessName'}).'#text'
        ProcessId   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'ProcessId'}).'#text'
        User        = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## Troubleshooting – Event 4689 Not Appearing

If you run the detection command and get no results, follow these steps:

**Step 1 – Confirm the audit policy is actually enabled:**
```powershell
auditpol /get /subcategory:"Process Termination"
```

**Step 2 – Re-enable and force update:**
```powershell
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
gpupdate /force
```

**Step 3 – Generate the event again:**
```powershell
$proc = Start-Process notepad.exe -PassThru
Start-Sleep -Seconds 4
Stop-Process -Id $proc.Id -Force
```

**Step 4 – Check again:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4689} -MaxEvents 5 | Format-List TimeCreated, Message
```

---

## SOC Analyst Notes

### Pairing 4688 and 4689 for Timeline Analysis

The real power of Event 4689 comes from combining it with 4688. The ProcessId field links both events together — same PID means same process.

```powershell
# See both process creation and termination together
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688,4689} -MaxEvents 20 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time      = $_.TimeCreated
        EventID   = $_.Id
        Process   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'NewProcessName' -or $_.Name -eq 'ProcessName'}).'#text'
        PID       = ($xml.Event.EventData.Data | Where {$_.Name -eq 'NewProcessId' -or $_.Name -eq 'ProcessId'}).'#text'
    }
} | Sort-Object Time | Format-Table -AutoSize
```

### What to Look For

| Scenario | Risk |
|----------|------|
| Process starts and exits in under 1 second | 🔴 Possible malware dropper |
| `cmd.exe` or `powershell.exe` runs briefly then exits | 🔴 Command execution, possible C2 |
| Process exits with no matching 4688 (log gap) | 🟡 Possible log tampering |
| Many processes starting and stopping rapidly | 🟡 Automated scanning or attack tool |
