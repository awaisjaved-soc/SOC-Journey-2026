# Event 5857 – WMI Activity Detected

**Log:** Microsoft-Windows-WMI-Activity/Operational  
**Event ID:** 5857  
**Severity:** Low – Medium  
**SOC Importance:** High (Baseline + Reconnaissance Detection)

---

## What is this Event?

Event 5857 is generated whenever a **WMI provider** is loaded and used.

A WMI provider is the component that answers WMI queries. For example:

- When you ask for running processes → `Win32_Process` provider is used
- When you ask for OS information → `Win32_OperatingSystem` provider is used

Every time a provider is called, Event 5857 can be logged.

### Why it matters in SOC

This event helps you:

- Establish a baseline of normal WMI activity
- Detect unusual WMI usage (possible reconnaissance)
- Spot lateral movement tools that heavily rely on WMI (e.g. Impacket, wmiexec)

Attackers frequently use WMI to gather system information before moving laterally or deploying persistence.

---

## How to Enable

```powershell
wevtutil sl Microsoft-Windows-WMI-Activity/Operational /e:true
```

Verify:

```powershell
wevtutil gl Microsoft-Windows-WMI-Activity/Operational
```

---

## How to Generate Event 5857

### PowerShell Method

```powershell
# These queries will generate Event 5857
Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version
Get-WmiObject -Class Win32_Process | Select-Object Name, ProcessId -First 8
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }
Get-WmiObject -Class Win32_ComputerSystem
```

### GUI Method

1. Open **Computer Management**
2. Go to **Services and Applications → WMI Control**
3. Right-click → **Properties**

This also triggers WMI activity.

---

## How to Detect

### Event Viewer

1. Open Event Viewer
2. Navigate to:  
   `Applications and Services Logs → Microsoft → Windows → WMI-Activity → Operational`
3. Filter by Event ID **5857**

### PowerShell

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-WMI-Activity/Operational'
    Id = 5857
    StartTime = (Get-Date).AddHours(-1)
} | Select-Object TimeCreated, Message | Format-List
```

---

## Key Fields to Analyze

| Field          | Meaning                                      |
|----------------|----------------------------------------------|
| ProviderName   | Which WMI provider was used                  |
| Namespace      | Usually `root\cimv2` (unusual ones are suspicious) |
| ClientProcessId| Process that made the WMI query              |
| User           | Account that performed the query             |
| ResultCode     | `0x0` = Success                              |

---

## SOC Analyst Notes

- High volume of 5857 from unusual processes = possible reconnaissance
- Combine with process creation (4688) to see who launched the WMI activity
- Remote WMI activity is more suspicious than local

---

**Related Events:** 5858, 5860, 5861
