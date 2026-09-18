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

<img width="468" height="329" alt="Screenshot_1" src="https://github.com/user-attachments/assets/0f98ab3e-1bd7-4bc5-a207-e2c3ab2a2b23" />

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

---

<img width="468" height="329" alt="Screenshot_1" src="https://github.com/user-attachments/assets/a66f6b29-818e-4aab-b418-1ac8caa13f3d" />

---

<img width="468" height="330" alt="Screenshot_2" src="https://github.com/user-attachments/assets/734b99d2-6635-4e69-b9db-67330eee94bf" />

---

<img width="468" height="327" alt="Screenshot_3" src="https://github.com/user-attachments/assets/1aaf7b35-86bb-478d-8fe2-16028b736d60" />

---

<img width="468" height="332" alt="Screenshot_4" src="https://github.com/user-attachments/assets/6b3a0c90-1105-4a4e-a4f1-46c31a385d64" />

---



Each of these creates a new process and generates an Event ID 1.

### Method 2: PowerShell (Recommended)

```powershell
Start-Process notepad.exe
Start-Process calc.exe
Start-Process cmd.exe
Start-Process powershell.exe
```

---


<img width="871" height="62" alt="Screenshot_5" src="https://github.com/user-attachments/assets/c8d262f9-2ada-405e-9b86-845c22f85e8a" />

---


## Detection Commands

### Basic View

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1]]" -MaxEvents 10 |
Select-Object TimeCreated, Id, Message |
Format-List
```

---

<img width="642" height="128" alt="Screenshot_14" src="https://github.com/user-attachments/assets/b7598ac4-aaf6-4b75-ae56-d1a61ddb5fa0" />

---

<img width="950" height="477" alt="Screenshot_6" src="https://github.com/user-attachments/assets/9825ea1a-58e4-430d-b467-6eca2719803c" />

---


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

<img width="812" height="331" alt="Screenshot_7" src="https://github.com/user-attachments/assets/5d8990b8-5da0-4434-8b3c-f0f0423f995b" />

---


<img width="711" height="334" alt="Screenshot_8" src="https://github.com/user-attachments/assets/7625b579-cb1a-4258-852f-92e0aceeb227" />


---

<img width="783" height="330" alt="Screenshot_9" src="https://github.com/user-attachments/assets/56fc057d-b463-4e2f-bb36-2e84a60afc86" />

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
