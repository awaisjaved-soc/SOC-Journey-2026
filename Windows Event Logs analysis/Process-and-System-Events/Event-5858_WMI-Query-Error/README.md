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

<img width="467" height="328" alt="Screenshot_2" src="https://github.com/user-attachments/assets/c3c80c5c-370b-4eae-85ab-f192f232424f" />

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

<img width="644" height="446" alt="Screenshot_1" src="https://github.com/user-attachments/assets/c3a040b5-32b4-40ec-8128-5fa5464cf9b1" />

---

<img width="855" height="383" alt="Screenshot_7" src="https://github.com/user-attachments/assets/16c74fd0-3ba0-4c32-a748-8767c7a15421" />

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

<img width="675" height="385" alt="Screenshot_3" src="https://github.com/user-attachments/assets/9d8e68bd-4b20-49bb-a9b0-ee058520ad4c" />

---

## Key Fields

| Field             | What to Look For                                       |
|-------------------|--------------------------------------------------------|
| ResultCode        | Non-zero error code (e.g. 0x80041010 = Invalid Class)  |
| ClientProcessId   | PID of the process that made the failed query          |
| NamespaceName     | Namespace that was queried                             |
| User              | Account that performed the query                       |

---

<img width="885" height="392" alt="Screenshot_4" src="https://github.com/user-attachments/assets/61275c72-0126-456b-8f2e-70777c40caf7" />

---

## SOC Analyst Notes

- Occasional 5858 events are normal
- Sudden spike in failures = possible reconnaissance
- Always investigate the ClientProcessId and the user account behind the failed queries

---

**Related Events:** 5857, 5860, 5861
