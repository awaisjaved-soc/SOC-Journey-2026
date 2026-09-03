# Event 7036 – Service Started or Stopped

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 7036 |
| **Category** | Process & System Events |
| **Log** | System |
| **Tier** | 🟠 Tier 2 – High Value |
| **SOC Importance** | 🟡 Medium |

## What Is This Event?

Event 7036 is generated every time a **service enters the running state or the stopped state**. It is one of the most common events in the System log and provides baseline visibility into service activity across the entire system.

While most 7036 events are completely normal, this event becomes critical when:
- **Security services** like Windows Defender, Event Log, or Firewall are stopped
- **Monitoring agents** like Wazuh or Splunk forwarders are stopped unexpectedly
- An **unknown service** starts at unusual hours
- A service stops and never restarts — indicating it may have been disabled

---

## Audit Policy

Event 7036 is logged in the **System log by default** — no audit policy required.

---

## How to Generate This Event

### Method 1 – GUI (Services Manager)
1. Press `Win + R` → type `services.msc` → Enter
2. Right-click any service → **Stop** → generates 7036 (stopped)
3. Right-click again → **Start** → generates 7036 (running)

### Method 2 – PowerShell (Create and Control Test Service)
```powershell
# Create a test service
New-Service -Name "TestService7036" `
  -BinaryPathName "C:\Windows\System32\notepad.exe" `
  -StartupType Manual

# Start the service (generates 7036 – running state)
Start-Service -Name "TestService7036" -ErrorAction SilentlyContinue

# Stop the service (generates 7036 – stopped state)
Stop-Service -Name "TestService7036" -ErrorAction SilentlyContinue
```

### Method 3 – sc.exe
```powershell
sc.exe start "TestService7036"
sc.exe stop "TestService7036"
```

### Method 4 – Using a Real Windows Service (Safe Lab Example)
```powershell
# Stop Print Spooler (safe to stop in lab environment)
Stop-Service -Name "Spooler"

# Start it back immediately
Start-Service -Name "Spooler"
```

---

## How to Detect This Event

### GUI Method
1. Open **Event Viewer** (`eventvwr.msc`)
2. Go to **Windows Logs → System**
3. Click **Filter Current Log**
4. Enter Event ID: `7036`
5. Click OK

### PowerShell Method
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7036} -MaxEvents 10 |
ForEach-Object {
    [PSCustomObject]@{
        Time    = $_.TimeCreated
        Message = $_.Message
    }
} | Format-Table -AutoSize -Wrap
```

### Detect Security Services Being Stopped
```powershell
# Focus only on security-critical services being stopped
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7036} -MaxEvents 50 |
Where-Object {
    $_.Message -match "stopped" -and
    $_.Message -match "Defender|WinDefend|MsMpEng|EventLog|Firewall|Wazuh|Splunk|MBAMService"
} | Select-Object TimeCreated, Message | Format-List
```

### See All Service State Changes in Last Hour
```powershell
$oneHourAgo = (Get-Date).AddHours(-1)
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Id = 7036
    StartTime = $oneHourAgo
} | Select-Object TimeCreated, Message | Format-Table -AutoSize -Wrap
```

---

## Cleanup After Lab

```powershell
sc.exe delete "TestService7036"
# Start Spooler back if you stopped it
Start-Service -Name "Spooler" -ErrorAction SilentlyContinue
```

---

## SOC Analyst Notes

### What to Look For

| Scenario | Risk |
|----------|------|
| Windows Defender service stopped | 🔴 Critical — AV disabled |
| Windows Event Log service stopped | 🔴 Critical — logging killed |
| Firewall service stopped | 🔴 Critical — network protection removed |
| Wazuh or Splunk agent stopped | 🔴 SIEM visibility lost |
| Unknown service starts at 3 AM | 🟡 Investigate immediately |
| Monitoring agent stopped unexpectedly | 🔴 Possible tampering |
| Service stops and never restarts | 🟡 Check if disabled via 7040 |

### High-Value Services to Monitor in 7036

| Service Name | Display Name | Why It Matters |
|-------------|-------------|----------------|
| `WinDefend` | Windows Defender | AV protection |
| `EventLog` | Windows Event Log | Logging itself |
| `MpsSvc` | Windows Firewall | Network protection |
| `wuauserv` | Windows Update | Patch management |
| `BITS` | Background Intelligent Transfer | Often abused for downloads |

### Related Events

| Event ID | Log | Relationship |
|----------|-----|-------------|
| 7045 | System | Service installed before starting |
| 7040 | System | Start type changed (may explain why service stopped) |
| 7000 | System | Service failed to start |
| 4697 | Security | Security log installation record |
