# Sysmon Event ID 5 – Process Terminated

## Overview

| Field        | Details                              |
|--------------|--------------------------------------|
| **Event ID** | 5                                    |
| **Category** | Process & System Events              |
| **Name**     | Process Terminated                   |
| **Log**      | Microsoft-Windows-Sysmon/Operational |
| **Importance** | Medium                             |

---


<img width="468" height="328" alt="Screenshot_2" src="https://github.com/user-attachments/assets/d348330c-4a9d-4a54-a4a9-461254b3c843" />

---


## What Is Event ID 5?

**Event ID 5 (Process Terminated)** is the counterpart to Event ID 1. It is generated every time a process exits or is terminated.

On its own, Event ID 5 is not as critical as Event ID 1. Its real power comes when you **pair it with Event ID 1** to build a complete picture of a process's lifetime — when it started, what it did, and when it ended.

This event helps detect:
- Short-lived processes that run, execute a task, and immediately die (a common malware pattern)
- Processes that were forcefully killed
- Building accurate timelines for incident response
- Correlating start and end times with other suspicious activity in the same window

---

## Key Fields

| Field        | Meaning                                               |
|--------------|-------------------------------------------------------|
| `Image`      | Full path of the process that was terminated          |
| `ProcessId`  | PID of the terminated process                         |
| `User`       | User account under which the process was running      |
| `UtcTime`    | UTC timestamp when the process ended                  |

---

## Relationship with Event ID 1

| Event | What Happens           | When             |
|-------|------------------------|------------------|
| **1** | Process Created        | Process starts   |
| **5** | Process Terminated     | Process ends     |

By matching the `ProcessId` and `Image` fields across Event ID 1 and Event ID 5, you can calculate exactly how long any process ran. A process that starts and dies within a few seconds deserves closer attention.

---

## How to Generate Event ID 5

### Method: PowerShell

```powershell
# Start a process
Start-Process notepad.exe

# Wait a few seconds
Start-Sleep -Seconds 3

# Forcefully kill the process — this generates Event ID 5
Stop-Process -Name notepad -Force
```

---

<img width="661" height="109" alt="Screenshot_4" src="https://github.com/user-attachments/assets/81a5b8dc-5c0f-47f8-b8c2-b5965047fcef" />

---

<img width="537" height="82" alt="Screenshot_3" src="https://github.com/user-attachments/assets/0b853b05-b004-49ba-9188-330167a1dbf4" />

---

<img width="765" height="406" alt="sasdasdad" src="https://github.com/user-attachments/assets/06cc53a6-0e4a-48e0-baf2-79b20f8cba2d" />

---


## Detection Commands

### Basic View

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=5]]" -MaxEvents 10 |
Select-Object TimeCreated, Id, Message | Format-List
```
---

<img width="609" height="89" alt="Screenshot_1" src="https://github.com/user-attachments/assets/dcb00efe-6f28-47f7-a3ea-ffbd6d37de07" />

### Detailed View (Recommended)

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=5]]" -MaxEvents 10 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time    = $_.TimeCreated
        Process = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'}).'#text'
        User    = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'}).'#text'
        PID     = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'}).'#text'
    }
} | Format-Table -AutoSize -Wrap
```

### Pair Event ID 1 and Event ID 5 for a Process Lifetime View

```powershell
# Get process creation events
$creations = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1]]" -MaxEvents 50 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Event   = "Created"
        Time    = $_.TimeCreated
        Process = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'}).'#text'
        PID     = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'}).'#text'
    }
}

# Get process termination events
$terminations = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=5]]" -MaxEvents 50 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Event   = "Terminated"
        Time    = $_.TimeCreated
        Process = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'}).'#text'
        PID     = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'}).'#text'
    }
}

# Combine and sort by time
$combined = $creations + $terminations
$combined | Sort-Object Time | Format-Table -AutoSize -Wrap
```

---

## Normal vs Suspicious Activity

| Indicator             | Normal                                             | Suspicious                                          |
|-----------------------|----------------------------------------------------|-----------------------------------------------------|
| **Lifetime**          | Browser, Office app runs for minutes or hours      | Process starts, runs for 1–3 seconds, then exits    |
| **Process path**      | `C:\Windows\System32\...`                          | `C:\Temp\`, `C:\Users\Public\`, `AppData`           |
| **Who terminated it** | User closed the app normally                       | `SYSTEM` forcefully killing security tools          |

---

## SOC Analyst Notes

- Event ID 5 alone is low value. It becomes useful when **correlated with Event ID 1** using the same PID or process image.
- A process that creates files, makes network connections, and terminates within seconds should be investigated. This is a pattern common to droppers and stagers.
- Security tools being forcefully terminated (antivirus, EDR, monitoring agents) and generating Event ID 5 is a strong indicator of tamper behavior.

---

## Key Takeaways

- Event ID 5 = A process exited
- Best used paired with Event ID 1 to measure process lifetime
- Very short-lived processes from suspicious paths are a red flag
- Useful for building complete investigation timelines

---

*Lab environment: Windows Server 2022 – SOC Journey 2026*
