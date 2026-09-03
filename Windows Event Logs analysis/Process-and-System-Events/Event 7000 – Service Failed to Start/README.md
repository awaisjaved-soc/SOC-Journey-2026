# Event 7000 – Service Failed to Start

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 7000 |
| **Category** | Process & System Events |
| **Log** | System |
| **Tier** | 🟠 Tier 2 – High Value |
| **SOC Importance** | 🟡 Medium–High |

## What Is This Event?

Event 7000 is generated when a **service fails to start**. This can happen for legitimate reasons like a missing binary, corrupt file, or misconfiguration — but in a security context it is important because:

- A **malicious service** may fail to start because its binary was deleted by AV or the path was wrong
- A **tampered service** may fail because its executable was modified or removed
- **Repeated failures** of the same service in a short time indicate something worth investigating
- Malware that installs a service with an invalid or missing binary will always generate this event when Windows tries to start it

> **Lab Note:** In earlier labs, when `notepad.exe` or a fake path was used as a service binary and the service was started, Event 7000 was the event that actually fired — not 7034. This is because 7000 covers services that **fail to start**, while 7034 covers services that **start successfully but then crash**. Both are important but serve different detection scenarios.

---

## Audit Policy

Event 7000 is logged in the **System log by default** — no audit policy required.

---

## How to Generate This Event

### Method 1 – Service With Invalid Binary Path (Recommended)
```powershell
# Create a service pointing to a non-existent file
sc.exe create "CrashTestService" binPath= "C:\FakeFolder\fake.exe" start= auto

# Try to start it — it will fail and generate Event 7000
sc.exe start "CrashTestService"
```

### Method 2 – PowerShell
```powershell
# Create service with invalid path
New-Service -Name "FailService7000" `
  -BinaryPathName "C:\invalid\path\missing.exe" `
  -StartupType Automatic

# Attempt to start it (generates 7000)
Start-Service -Name "FailService7000" -ErrorAction SilentlyContinue
```

### Method 3 – Simulate Malware Service Failing
```powershell
# Mimics what happens when AV deletes malware binary after service is created
New-Service -Name "MalwareSimSvc" `
  -BinaryPathName "C:\Users\Public\payload.exe" `
  -StartupType Automatic

# payload.exe does not exist so starting it fails — generates 7000
Start-Service -Name "MalwareSimSvc" -ErrorAction SilentlyContinue
```

---

## How to Detect This Event

### GUI Method
1. Open **Event Viewer** (`eventvwr.msc`)
2. Go to **Windows Logs → System**
3. Click **Filter Current Log**
4. Enter Event ID: `7000`
5. Click OK

### PowerShell Method
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7000} -MaxEvents 5 |
ForEach-Object {
    [PSCustomObject]@{
        Time    = $_.TimeCreated
        Message = $_.Message
    }
} | Format-List
```

### Find Services Failing Repeatedly
```powershell
# Group to find services failing multiple times
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7000} -MaxEvents 30 |
Group-Object Message |
Select-Object Count, Name |
Sort-Object Count -Descending |
Format-Table -AutoSize -Wrap
```

### Search for Suspicious Service Failures
```powershell
# Look for unknown or suspicious service names in failures
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7000} -MaxEvents 20 |
Where-Object {
    $_.Message -notmatch "Diagnostic|Update|Windows|Print|Audio|Network"
} | Select-Object TimeCreated, Message | Format-List
```

---

## Cleanup After Lab

```powershell
sc.exe delete "CrashTestService"
sc.exe delete "FailService7000"
sc.exe delete "MalwareSimSvc"
```

---

## 7000 vs 7034 – Key Difference

| Event | When It Fires | Scenario |
|-------|--------------|----------|
| **7000** | Service **failed to start** | Binary missing, path wrong, permissions issue |
| **7034** | Service **started but then crashed** | Service ran, then terminated unexpectedly |

In most lab environments with fake binary paths, **7000 is what you will see** — not 7034. Event 7034 requires the service to actually start first before crashing.

---

## SOC Analyst Notes

| Scenario | Risk |
|----------|------|
| Unknown service fails to start repeatedly | 🔴 Malware binary possibly deleted by AV |
| Service failure after a new installation event (7045) | 🔴 Correlate — new malware service failing |
| Security or monitoring service fails | 🔴 Possible tampering |
| Legitimate service fails after a Windows update | 🟡 Investigate recent changes |
| Multiple different services failing at same time | 🟡 System issue or attack in progress |

### Attack Correlation

```
7045 – "MalwareService" installed pointing to C:\Users\Public\payload.exe
4688 – Windows attempts to launch payload.exe
7000 – Service failed to start (AV deleted payload.exe before it ran)
```

This chain means AV caught the malware — but the service entry still exists and may be retried.

### Related Events

| Event ID | Log | Relationship |
|----------|-----|-------------|
| 7045 | System | Service was installed before failing |
| 4697 | Security | Security log record of same installation |
| 7034 | System | Service crashed after successfully starting |
| 7036 | System | Service state change (started/stopped) |
