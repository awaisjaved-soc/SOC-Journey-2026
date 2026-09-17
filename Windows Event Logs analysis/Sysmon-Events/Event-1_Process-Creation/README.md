# Sysmon Event ID 1 – Process Creation

## Overview

| Field        | Details                            |
|--------------|------------------------------------|
| **Event ID** | 1                                  |
| **Category** | Process & System Events            |
| **Name**     | Process Creation                   |
| **Log**      | Microsoft-Windows-Sysmon/Operational |
| **Importance** | Critical                         |

---

## What Is Event ID 1?

**Event ID 1 (Process Creation)** is generated every time a new process starts on the system.

It is one of the most critical Sysmon events because it gives full visibility into what is being executed on a machine. Unlike the basic Windows Security log (Event ID 4688), Sysmon's Event ID 1 includes much richer detail such as the full command line, hashes, parent process, and the user who triggered the execution.

This event helps detect:
- Malware execution
- Living-off-the-land (LOLBin) abuse
- Suspicious parent-child process chains (e.g. `winword.exe` spawning `cmd.exe`)
- Encoded PowerShell commands
- Processes running from unusual locations (Temp, AppData, Public, Downloads)

---

## Key Fields

| Field              | Meaning                                                        |
|--------------------|----------------------------------------------------------------|
| `Image`            | Full path of the process that was created                      |
| `CommandLine`      | Full command line used to launch the process                   |
| `ParentImage`      | Full path of the parent process that spawned this one          |
| `ParentCommandLine`| Command line of the parent process                             |
| `User`             | The user account that ran the process                          |
| `Hashes`           | MD5, SHA256, and other hashes of the executable                |
| `ProcessId`        | Process ID (PID) of the new process                            |
| `ParentProcessId`  | PID of the parent process                                      |
| `UtcTime`          | UTC timestamp of when the process started                      |

---

## How to Generate Event ID 1

### Method 1: GUI

1. Open Notepad
2. Open Calculator
3. Open Command Prompt
4. Open PowerShell

Each of these creates a new process and generates an Event ID 1.

### Method 2: PowerShell (Recommended)

```powershell
Start-Process notepad.exe
Start-Process calc.exe
Start-Process cmd.exe
Start-Process powershell.exe
```

---

## Detection Commands

### Basic View

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1]]" -MaxEvents 10 |
Select-Object TimeCreated, Id, Message |
Format-List
```

### Detailed View (Recommended)

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1]]" -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time          = $_.TimeCreated
        Process       = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'}).'#text'
        CommandLine   = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'}).'#text'
        ParentProcess = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ParentImage'}).'#text'
        User          = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'}).'#text'
    }
} | Format-Table -AutoSize -Wrap
```

---

## Normal vs Suspicious Activity

| Indicator        | Normal Example                                  | Suspicious Example                                      |
|------------------|-------------------------------------------------|---------------------------------------------------------|
| **Process path** | `C:\Windows\System32\notepad.exe`               | `C:\Users\Public\update.exe` or `C:\Temp\payload.exe`  |
| **Parent process**| `explorer.exe` spawning `notepad.exe`          | `winword.exe` spawning `cmd.exe` or `powershell.exe`   |
| **Command line** | `notepad.exe`                                   | `powershell.exe -EncodedCommand <base64>`               |
| **User**         | Standard domain user                            | `SYSTEM` running something unusual                      |

---

## SOC Analyst Notes

When analyzing Event ID 1, ask yourself:

1. **Is the process path expected?** Processes in Temp, AppData, Public, or Downloads are red flags.
2. **Is the parent-child relationship normal?** Office apps, browsers, or PDF readers spawning `cmd.exe` or `powershell.exe` is a major red flag.
3. **Is the command line suspicious?** Encoded commands, long obfuscated strings, or use of LOLBins (certutil, regsvr32, mshta, wscript) are all suspicious.
4. **Is the hash known malicious?** Submit to VirusTotal if unsure.

**Common LOLBins to watch:**
- `powershell.exe`, `cmd.exe`
- `certutil.exe`, `regsvr32.exe`, `mshta.exe`
- `wscript.exe`, `cscript.exe`
- `rundll32.exe`, `msiexec.exe`

---

## Key Takeaways

- Event ID 1 = A new process was created
- Contains full command line, parent, user, and hashes
- Richer than Windows native 4688 event
- Focus on parent-child chains, suspicious paths, and encoded commands
- `svchost.exe` and `explorer.exe` appearing frequently is completely normal

---

*Lab environment: Windows Server 2022 – SOC Journey 2026*
