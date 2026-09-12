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

<img width="948" height="488" alt="Screenshot_4" src="https://github.com/user-attachments/assets/28835639-ec38-459f-9e8f-f48b7f68987d" />

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
---

<img width="675" height="183" alt="Screenshot_6" src="https://github.com/user-attachments/assets/9d237b77-f5d3-43c8-b943-561dafd95de8" />

---

### GUI Method

1. Open **Computer Management**
2. Expand **Services and Applications**
3. Right-click **WMI Control** → **Properties**

This also triggers WMI activity and generates Event 5857.

---

<img width="676" height="383" alt="Screenshot_2" src="https://github.com/user-attachments/assets/ddeccdfa-9fb3-49be-b61b-be86c933e13f" />

---

## How to Detect

### Event Viewer (GUI)

1. Open Event Viewer
2. Navigate to:  
   `Applications and Services Logs → Microsoft → Windows → WMI-Activity → Operational`
3. Filter Current Log → Event ID: **5857**

---

<img width="633" height="432" alt="Screenshot_3" src="https://github.com/user-attachments/assets/92cd67a2-b50d-42bc-8f53-83d533a677e7" />

---


### PowerShell Detection

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-WMI-Activity/Operational'
    Id        = 5857
    StartTime = (Get-Date).AddHours(-1)
} | Select-Object TimeCreated, Message | Format-List
```

---

<img width="674" height="224" alt="Screenshot_5" src="https://github.com/user-attachments/assets/f2f7b707-e022-455b-879c-3efc95b4b649" />

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

<img width="674" height="380" alt="Screenshot_1" src="https://github.com/user-attachments/assets/7091b63e-5d91-464d-b335-006e8cc4f151" />

---
## SOC Analyst Notes

- High volume of 5857 from unusual processes can indicate reconnaissance
- Always correlate with process creation events (4688)
- Remote WMI activity is generally more suspicious than local activity
- Baseline normal WMI usage in your environment for better detection

---

**Related Events:** 5858, 5860, 5861
