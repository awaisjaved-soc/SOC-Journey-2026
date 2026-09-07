# Event 5858 – WMI Query Error

**Log:** Microsoft-Windows-WMI-Activity/Operational  
**Event ID:** 5858  
**Severity:** Medium  
**SOC Importance:** Medium-High

---

## What is this Event?

Event 5858 is logged when a **WMI query fails**.

This happens when:

- The requested WMI class does not exist
- The namespace is invalid
- There is a syntax error in the query
- Access is denied

### Why it matters in SOC

Attackers often generate many failed WMI queries while performing reconnaissance on a system they do not fully understand. A sudden burst of Event 5858 can indicate someone is probing the system through WMI.

---

## How to Enable

Same as other WMI events:

```powershell
wevtutil sl Microsoft-Windows-WMI-Activity/Operational /e:true
```

---

## How to Generate Event 5858

```powershell
# Intentionally cause WMI errors
try {
    Get-WmiObject -Class Win32_FakeClassThatDoesNotExist -ErrorAction Stop
} catch {
    Write-Host "Expected error occurred"
}

try {
    Get-WmiObject -Namespace "root\FakeNamespace" -Class Win32_Process -ErrorAction Stop
} catch {
    Write-Host "Expected error occurred"
}
```

---

## How to Detect

### Event Viewer

Filter **WMI-Activity/Operational** for Event ID **5858**

### PowerShell

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-WMI-Activity/Operational'
    Id = 5858
    StartTime = (Get-Date).AddHours(-1)
} | Select-Object TimeCreated, Message | Format-List
```

---

## Key Fields

| Field            | Meaning                                      |
|------------------|----------------------------------------------|
| ResultCode       | Error code (e.g. 0x80041010 = Invalid Class) |
| ClientProcessId  | Process that made the failed query           |
| NamespaceName    | Namespace that was queried                   |
| User             | Account that made the query                  |

---

## SOC Analyst Notes

- Occasional 5858 events are normal
- Sudden spike in 5858 = possible reconnaissance
- Always correlate with the ClientProcessId and user account

---

**Related Events:** 5857, 5860, 5861
