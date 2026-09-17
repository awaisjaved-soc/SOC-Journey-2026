# Sysmon Event ID 11 — File Create

**Log Name:** Microsoft-Windows-Sysmon/Operational  
**Source:** Sysmon  
**Level:** Information  
**Lab Status:** ✅ Successfully Generated

---

## Long Introduction

Event ID 11 (File Create) is generated whenever a process creates a new file on the system.

This is one of the most useful Sysmon events for detecting malware activity because almost every malware drops files on disk (executables, scripts, configuration files, ransomware notes, etc.).

With Event ID 11, a SOC analyst can see:

- Which process created the file
- The full path of the created file
- The user who created it
- When the file was created

This event helps detect:

- Malware dropping payloads
- Ransomware creating encrypted files
- Scripts or tools writing to disk
- Persistence mechanisms (dropping files in startup folders)
- Suspicious file creation by Office applications or browsers

---

## Key Fields

| Field            | Meaning                             |
|------------------|-------------------------------------|
| Image            | The process that created the file   |
| TargetFilename   | Full path of the newly created file |
| User             | Account that created the file       |
| CreationUtcTime  | Original creation time of the file  |
| ProcessId        | Process ID of the creator           |

---

## How to Generate Event ID 11

### Method 1: GUI
1. Open Notepad
2. Type some text
3. Save the file (e.g. on Desktop or in Public folder)

### Method 2: PowerShell (Recommended)

```powershell
# Create test files
"This is a test file for Sysmon Event ID 11" | Out-File -FilePath "C:\Users\Public\Sysmon_Test_1.txt"
"Another test file" | Out-File -FilePath "C:\Users\Public\Sysmon_Test_2.txt"

# Create a folder and a file inside it
New-Item -Path "C:\Users\Public\Sysmon_Test_Folder" -ItemType Directory -Force
"Lab file" | Out-File -FilePath "C:\Users\Public\Sysmon_Test_Folder\labfile.txt"
```

### Method 3: Command Prompt

```cmd
echo Sysmon Event 11 Test > C:\Users\Public\cmd_test.txt
```

---

## Detection Commands

### 1. Basic View

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=11]]" -MaxEvents 10 |
Select-Object TimeCreated, Id, Message | Format-List
```

### 2. Detailed View (Recommended)

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=11]]" -MaxEvents 15 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        Process     = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'}).'#text'
        FileCreated = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetFilename'}).'#text'
        User        = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'}).'#text'
    }
} | Format-Table -AutoSize -Wrap
```

### 3. Filter only interesting locations

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=11]]" -MaxEvents 20 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    $file = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetFilename'}).'#text'

    if ($file -like "*Public*") {
        [PSCustomObject]@{
            Time        = $_.TimeCreated
            Process     = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'}).'#text'
            FileCreated = $file
            User        = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'}).'#text'
        }
    }
} | Format-Table -AutoSize -Wrap
```

---

## Normal vs Suspicious File Creation

| Indicator   | Normal Example                          | Suspicious Example                                  |
|-------------|-----------------------------------------|-----------------------------------------------------|
| Path        | C:\Windows\ServiceState\...             | C:\Users\Public\, Temp, AppData, Downloads          |
| Process     | svchost.exe, services.exe               | powershell.exe, cmd.exe, unknown .exe               |
| File Type   | .dat, system files                      | .exe, .dll, .ps1, .bat, .vbs, .js                   |
| User        | NT AUTHORITY\LOCAL SERVICE, SYSTEM      | Normal user or strange accounts                     |

---

## What SOC Analysts Look For

- Executable or script files created in user-writable locations
- Files created by Office applications that are executables
- Browsers or email clients dropping executable files
- Large number of files created in a short time (possible ransomware)
- Files created in Startup folders or other persistence locations

---

## Key Learning Points

- Event ID 11 = A process created a new file
- Many events are normal system activity (especially from svchost.exe)
- Focus on **where** the file was created and **which process** created it
- Files created in Public, Temp, AppData, or with dangerous extensions deserve extra attention
