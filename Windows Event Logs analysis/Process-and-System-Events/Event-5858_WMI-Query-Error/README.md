# Event 5858 — WMI Query Error

**Log Name:** Microsoft-Windows-WMI-Activity/Operational  
**Event ID:** 5858  
**Level:** Error  
**SOC Severity:** Medium  
**MITRE ATT&CK:** T1047 – Windows Management Instrumentation

---

## What Is This Event?

Event 5858 is logged when a **WMI query fails**.

Common reasons for failure:

- The requested WMI class does not exist
- The namespace is invalid or inaccessible
- Syntax error in the WQL query
- Access denied

### Why It Matters for SOC

When attackers perform WMI-based reconnaissance on a system they do not fully understand, they often generate multiple failed queries. A sudden burst of Event 5858 can be an early indicator of someone probing the system through WMI.

Failed reconnaissance still leaves a trail.

---

## How to Generate Event 5858

```powershell
# Intentionally cause WMI errors

try {
    Get-WmiObject -Class Win32_FakeClassThatDoesNotExist -ErrorAction Stop
} catch {
    Write-Host "Expected error: $($_.Exception.Message)"
}

try {
    Get-WmiObject -Namespace "root\FakeNamespace" -Class Win32_Process -ErrorAction Stop
} catch {
    Write-Host "Expected error: $($_.Exception.Message)"
}

try {
    $query = [wmiclass]"\\.\root\cimv2:Win32_NonExistentClass"
} catch {
    Write-Host "Expected error: $($_.Exception.Message)"
}
```

---

## How to Detect

### Event Viewer

Filter `WMI-Activity/Operational` for Event ID **5858**

### PowerShell

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-WMI-Activity/Operational'
    Id        = 5858
    StartTime = (Get-Date).AddHours(-1)
} | Select-Object TimeCreated, Message | Format-List
```

---

## Key Fields

| Field             | What to Look For                                       |
|-------------------|--------------------------------------------------------|
| ResultCode        | Non-zero error code (e.g. 0x80041010 = Invalid Class)  |
| ClientProcessId   | PID of the process that made the failed query          |
| NamespaceName     | Namespace that was queried                             |
| User              | Account that performed the query                       |

---

## SOC Analyst Notes

- Occasional 5858 events are normal
- Sudden spike in failures = possible reconnaissance
- Always investigate the ClientProcessId and the user account behind the failed queries

---

**Related Events:** 5857, 5860, 5861
