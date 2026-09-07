# Event 5860 – Temporary WMI Subscription Created

**Log:** Microsoft-Windows-WMI-Activity/Operational  
**Event ID:** 5860  
**Severity:** Medium  
**SOC Importance:** High

---

## What is this Event?

Event 5860 is generated when a **temporary WMI event subscription** is created.

A temporary subscription only lives while the creating process is running. Once the process ends or the system reboots, the subscription disappears.

### Difference from Permanent Subscription (5861)

| Type              | Survives Reboot? | Event ID |
|-------------------|------------------|----------|
| Temporary         | No               | 5860     |
| Permanent         | Yes              | 5861     |

---

## Why it matters in SOC

Even temporary subscriptions can be used by attackers to:

- Execute code when a specific process starts
- Monitor for certain system conditions
- Run actions without creating permanent persistence

---

## How to Generate Event 5860

```powershell
# Clean previous subscriptions
Get-EventSubscriber | Unregister-Event -Force -ErrorAction SilentlyContinue

# Create temporary subscription
$query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'win32calc.exe'"

Register-WmiEvent -Query $query -SourceIdentifier "CalcWatch" -Action {
    "WMI detected Calculator at $(Get-Date)" | Out-File "C:\Windows\Temp\WMI_Calc_Detected.txt" -Append
}

# Trigger it
Start-Process calc.exe
```

---

## How to Detect

### Event Viewer

Go to `WMI-Activity/Operational` and filter for **Event ID 5860**

### PowerShell

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-WMI-Activity/Operational'
    Id = 5860
} -MaxEvents 5 | Format-List TimeCreated, Message
```

---

## Key Fields

| Field              | Meaning                                      |
|--------------------|----------------------------------------------|
| NotificationQuery  | The WQL query being monitored                |
| PossibleCause      | Usually shows "Temporary"                    |
| ClientProcessId    | Process that created the subscription        |
| UserName           | Account that created it                      |

---

## SOC Analyst Notes

- Temporary subscriptions are less dangerous than permanent ones
- Still worth investigating if created by unusual processes or accounts
- Always check what action the subscription performs

---

**Related Events:** 5857, 5861
