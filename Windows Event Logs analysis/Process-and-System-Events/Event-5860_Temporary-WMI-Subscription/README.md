# Event 5860 — Temporary WMI Subscription Created

**Log Name:** Microsoft-Windows-WMI-Activity/Operational  
**Event ID:** 5860  
**Level:** Information  
**SOC Severity:** Medium  
**MITRE ATT&CK:** T1546.003 – WMI Event Subscription

---

## What Is This Event?

Event 5860 is generated when a **temporary WMI event subscription** is created.

A temporary subscription only exists while the creating process is running. When the process ends or the system reboots, the subscription is automatically removed.

### Temporary vs Permanent

| Type        | Survives Reboot? | Event ID |
|-------------|------------------|----------|
| Temporary   | No               | 5860     |
| Permanent   | Yes              | 5861     |

---

## Why It Matters for SOC

Even temporary subscriptions can be abused by attackers to:

- Execute code when a specific process starts
- Trigger actions based on system conditions
- Perform fileless execution without leaving permanent artifacts

---

## How to Generate Event 5860

```powershell
# Clean any existing subscriptions
Get-EventSubscriber | Unregister-Event -Force -ErrorAction SilentlyContinue
Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue

# Create temporary subscription (watch for Calculator)
$query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'win32calc.exe'"

Register-WmiEvent -Query $query -SourceIdentifier "CalcWatch" -Action {
    "WMI detected Calculator at $(Get-Date)" | Out-File "C:\Windows\Temp\WMI_Calc_Detected.txt" -Append
}

# Trigger the subscription
Start-Process calc.exe

# Verify
Start-Sleep -Seconds 3
Get-Content "C:\Windows\Temp\WMI_Calc_Detected.txt" -ErrorAction SilentlyContinue
```

---

## How to Detect

### Event Viewer

Go to `WMI-Activity → Operational` and filter for **Event ID 5860**

### PowerShell

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-WMI-Activity/Operational'
    Id = 5860
} -MaxEvents 5 | Format-List TimeCreated, Message
```

---

## Key Fields

| Field               | What to Look For                                      |
|---------------------|-------------------------------------------------------|
| NotificationQuery   | The WQL query that is being monitored                 |
| PossibleCause       | Usually shows "Temporary"                             |
| ClientProcessId     | Process that created the subscription                 |
| UserName            | Account that created the subscription                 |

---

## SOC Analyst Notes

- Temporary subscriptions are less dangerous than permanent ones
- Still investigate if created by unusual processes or accounts
- Always examine what action the subscription is configured to perform

---

**Related Events:** 5857, 5861
