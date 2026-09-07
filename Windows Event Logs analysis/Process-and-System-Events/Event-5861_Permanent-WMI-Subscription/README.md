# Event 5861 – Permanent WMI Subscription Created

**Log:** Microsoft-Windows-WMI-Activity/Operational  
**Event ID:** 5861  
**Severity:** Critical  
**SOC Importance:** Very High (Persistence Detection)

---

## What is this Event?

Event 5861 is logged when a **permanent WMI event subscription** is created.

This is one of the most dangerous persistence techniques available on Windows.

### Why Attackers Love Permanent WMI Subscriptions

- Survives reboots
- Runs with high privileges (often SYSTEM)
- No new files required (can be fileless)
- Not visible in Task Scheduler, Services, or Startup folders
- Harder for normal users and basic security tools to detect

This technique is mapped to **MITRE ATT&CK T1546.003 – Windows Management Instrumentation Event Subscription**.

---

## Components of a Permanent Subscription

A permanent WMI subscription has three parts:

1. **Event Filter** → What to watch for (e.g. system boot, time, process start)
2. **Event Consumer** → What action to take (run a command, script, etc.)
3. **Filter-to-Consumer Binding** → Links the filter to the consumer

When all three are created, Event **5861** is generated.

---

## How to Generate Event 5861 (Practical Lab)

```powershell
# Create permanent subscription (Attacker simulation)

$filterName   = "WindowsUpdateCheck"
$consumerName = "WindowsUpdateService"

# 1. Create Filter
$filter = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" -Arguments @{
    Name           = $filterName
    EventNamespace = "root\cimv2"
    QueryLanguage  = "WQL"
    Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 15 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second = 30"
}

# 2. Create Consumer
$consumer = Set-WmiInstance -Namespace "root\subscription" -Class "CommandLineEventConsumer" -Arguments @{
    Name                = $consumerName
    CommandLineTemplate = "cmd.exe /c echo Malware executed at %date% %time% >> C:\SOCLab\malware_executed.txt"
}

# 3. Bind them (Generates Event 5861)
Set-WmiInstance -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -Arguments @{
    Filter   = $filter
    Consumer = $consumer
}

Write-Host "[+] Permanent WMI Persistence Created" -ForegroundColor Red
```

---

## How to Detect

### Event Viewer

Filter `WMI-Activity/Operational` for **Event ID 5861**

### PowerShell (Recommended)

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-WMI-Activity/Operational'
    Id = 5861
} -MaxEvents 5 | Format-List TimeCreated, Message
```

### Hunt for Existing Permanent Subscriptions

```powershell
Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" |
    Where-Object { $_.Name -ne "SCM Event Log Filter" }

Get-WmiObject -Namespace "root\subscription" -Class "CommandLineEventConsumer"
```

---

## Cleanup (Mandatory after Lab)

```powershell
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
    Where-Object { $_.Filter -match "WindowsUpdateCheck" } | Remove-WmiObject

Get-WmiObject -Namespace root\subscription -Class __EventFilter |
    Where-Object { $_.Name -eq "WindowsUpdateCheck" } | Remove-WmiObject

Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
    Where-Object { $_.Name -eq "WindowsUpdateService" } | Remove-WmiObject
```

---

## SOC Analyst Notes

- **Any unexpected 5861 should be treated as high priority**
- Look for consumers that launch `cmd.exe`, `powershell.exe`, `wscript.exe`, or encoded commands
- Permanent WMI subscriptions are rarely used by legitimate software
- Always correlate with process creation events (4688)

---

**This is one of the most important events in the entire Process & System category.**
