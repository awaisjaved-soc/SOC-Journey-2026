# Event 5861 — Permanent WMI Subscription Created

**Log Name:** Microsoft-Windows-WMI-Activity/Operational  
**Event ID:** 5861  
**Level:** Information  
**SOC Severity:** Critical  
**MITRE ATT&CK:** T1546.003 – Windows Management Instrumentation Event Subscription

---

## What Is This Event?

Event 5861 is logged when a **permanent WMI event subscription** is created.

This is one of the stealthiest and most dangerous persistence techniques available on Windows. It is frequently used by APT groups and advanced malware.

### Why Permanent WMI Subscriptions Are Dangerous

- Survive system reboots
- Can run with SYSTEM privileges
- Leave minimal file system artifacts
- Not visible in Task Scheduler, Services, or Startup folders
- Extremely difficult for average users and basic AV to detect

A permanent WMI subscription consists of three components:

1. **Event Filter** — Defines what to watch for (boot, logon, time, process creation, etc.)
2. **Event Consumer** — Defines what action to take (run a command, script, etc.)
3. **Filter-to-Consumer Binding** — Links the filter to the consumer

When all three are created, Event **5861** is generated.

---

## How to Generate Event 5861 (Practical Lab)

> **Warning:** This creates real persistence. Always run the cleanup commands afterward.

```powershell
# ========== Create Permanent WMI Subscription ==========

$filterName   = "WindowsUpdateCheck"
$consumerName = "WindowsUpdateService"

# 1. Create the Event Filter
$filter = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" -Arguments @{
    Name           = $filterName
    EventNamespace = "root\cimv2"
    QueryLanguage  = "WQL"
    Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 15 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second = 30"
}

# 2. Create the Event Consumer
$consumer = Set-WmiInstance -Namespace "root\subscription" -Class "CommandLineEventConsumer" -Arguments @{
    Name                = $consumerName
    CommandLineTemplate = "cmd.exe /c echo Malware executed at %date% %time% >> C:\SOCLab\malware_executed.txt"
}

# 3. Create the Binding (This generates Event 5861)
Set-WmiInstance -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -Arguments @{
    Filter   = $filter
    Consumer = $consumer
}

Write-Host "[+] Permanent WMI Persistence Created Successfully" -ForegroundColor Red
Write-Host "[+] Event 5861 should now appear in the WMI-Activity log" -ForegroundColor Yellow
```

---

## How to Detect

### Event Viewer

Filter `WMI-Activity/Operational` for **Event ID 5861**

### PowerShell

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-WMI-Activity/Operational'
    Id = 5861
} -MaxEvents 5 | Format-List TimeCreated, Message
```

### Hunt for Existing Permanent Subscriptions

```powershell
Write-Host "=== Checking for Permanent WMI Subscriptions ===" -ForegroundColor Cyan

Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" |
    Where-Object { $_.Name -ne "SCM Event Log Filter" } |
    Select-Object Name, Query

Get-WmiObject -Namespace "root\subscription" -Class "CommandLineEventConsumer" |
    Select-Object Name, CommandLineTemplate
```

---

## Cleanup Commands (Mandatory)

```powershell
# Remove Binding
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
    Where-Object { $_.Filter -match "WindowsUpdateCheck" } | Remove-WmiObject

# Remove Filter
Get-WmiObject -Namespace root\subscription -Class __EventFilter |
    Where-Object { $_.Name -eq "WindowsUpdateCheck" } | Remove-WmiObject

# Remove Consumer
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
    Where-Object { $_.Name -eq "WindowsUpdateService" } | Remove-WmiObject

Write-Host "[+] Cleanup completed" -ForegroundColor Green
```

---

## SOC Analyst Notes

- Treat any unexpected Event 5861 as **high priority**
- Look for consumers that execute `cmd.exe`, `powershell.exe`, `wscript.exe`, or encoded commands
- Permanent WMI subscriptions are rarely used by legitimate software
- Always correlate with process creation (Event 4688) and other related activity

---

**This is one of the most important events in the entire Process & System Events category.**
