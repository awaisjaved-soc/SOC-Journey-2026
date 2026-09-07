# Event 5857 — WMI Activity Detected

**Log Name:** Microsoft-Windows-WMI-Activity/Operational  
**Event ID:** 5857  
**Level:** Information  
**SOC Severity:** Low – Medium  
**MITRE ATT&CK:** T1047 – Windows Management Instrumentation

---

## What Is This Event?

Event 5857 is generated whenever a **WMI provider** is loaded and used.

A WMI provider is the component that answers WMI queries. For example:

- Asking for running processes → uses the `Win32_Process` provider  
- Asking for OS information → uses the `Win32_OperatingSystem` provider  
- Asking for network configuration → uses the `Win32_NetworkAdapterConfiguration` provider

Every time a provider is called to answer a query, Event 5857 can be written.

### Why It Matters for SOC

This event is valuable for:

- Building a baseline of normal WMI activity on a system
- Detecting unusual or excessive WMI usage (possible reconnaissance)
- Identifying lateral movement tools that heavily rely on WMI (Impacket, wmiexec, etc.)

Attackers frequently use WMI during the reconnaissance phase to gather system information before deploying persistence or moving laterally.

---

## Pre-Lab Setup

```powershell
# Enable WMI Operational Log
wevtutil sl Microsoft-Windows-WMI-Activity/Operational /e:true

# Verify it is enabled
wevtutil gl Microsoft-Windows-WMI-Activity/Operational
```

---

## How to Generate Event 5857

### PowerShell Method

```powershell
# These commands will generate Event 5857
Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version
Get-WmiObject -Class Win32_Process | Select-Object Name, ProcessId -First 10
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }
Get-WmiObject -Class Win32_ComputerSystem
Get-WmiObject -Class Win32_Product | Select-Object Name, Version -First 5
```

### GUI Method

1. Open **Computer Management**
2. Expand **Services and Applications**
3. Right-click **WMI Control** → **Properties**

This also triggers WMI activity and generates Event 5857.

---

## How to Detect

### Event Viewer (GUI)

1. Open Event Viewer
2. Navigate to:  
   `Applications and Services Logs → Microsoft → Windows → WMI-Activity → Operational`
3. Filter Current Log → Event ID: **5857**

### PowerShell Detection

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-WMI-Activity/Operational'
    Id        = 5857
    StartTime = (Get-Date).AddHours(-1)
} | Select-Object TimeCreated, Message | Format-List
```

---

## Key Fields to Analyze

| Field            | What to Look For                                      |
|------------------|-------------------------------------------------------|
| ProviderName     | Which WMI provider was used (e.g. Win32_Process)      |
| Namespace        | Usually `root\cimv2` — unusual namespaces are suspicious |
| ClientProcessId  | Process that made the WMI query                       |
| User             | Account that performed the activity                   |
| ResultCode       | `0x0` = Success                                       |

---

## SOC Analyst Notes

- High volume of 5857 from unusual processes can indicate reconnaissance
- Always correlate with process creation events (4688)
- Remote WMI activity is generally more suspicious than local activity
- Baseline normal WMI usage in your environment for better detection

---

**Related Events:** 5858, 5860, 5861
