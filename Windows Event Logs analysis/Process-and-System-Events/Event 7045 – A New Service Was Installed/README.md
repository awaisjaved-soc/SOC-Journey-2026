# Event 7045 – A New Service Was Installed

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 7045 |
| **Category** | Process & System Events |
| **Log** | System |
| **Tier** | 🟠 Tier 2 – High Value |
| **SOC Importance** | 🔴 High |

## What Is This Event?

Event 7045 is generated when a **new service is installed on the system**. It is logged in the **System** event log. This is one of the most important persistence events because malware frequently installs itself as a Windows service to survive reboots and run automatically in the background.

Attackers also use tools like Metasploit and Cobalt Strike which install services as part of their post-exploitation process. Any unexpected service installation — especially outside business hours or by a non-admin — should be treated as suspicious and investigated immediately.

> **Lab Note:** When you use `notepad.exe` or any GUI program as the service binary in a lab, it will NOT appear on screen. This is completely normal and expected. Services run under the **SYSTEM account** which has no desktop session. The event still fires correctly in the log — that is what matters for detection. In a real attack, malware runs the same way — invisibly in the background.

---

## Audit Policy

Event 7045 is logged in the **System log by default** — no special audit policy required. Just verify the System log is active:

```powershell
Get-WinEvent -ListLog System | Select-Object LogName, IsEnabled
```

---

## How to Generate This Event

### Method 1 – PowerShell (Basic)
```powershell
New-Service -Name "TestService7045" `
  -BinaryPathName "C:\Windows\System32\notepad.exe" `
  -DisplayName "Test SOC Service" `
  -Description "Lab service for Event 7045" `
  -StartupType Manual
```

### Method 2 – sc.exe (Simulates Attacker Method)
```powershell
# Attackers commonly use sc.exe to install services
sc.exe create "AttackerService" binPath= "C:\Windows\System32\cmd.exe" start= auto
```

### Method 3 – Simulate Malware Installing a Service
```powershell
# Points to a suspicious path like real malware would
New-Service -Name "WindowsUpdateHelper" `
  -BinaryPathName "C:\Users\Public\update.exe" `
  -StartupType Automatic `
  -DisplayName "Windows Update Helper"
```

---

## How to Detect This Event

### GUI Method
1. Open **Event Viewer** (`eventvwr.msc`)
2. Go to **Windows Logs → System**
3. Click **Filter Current Log**
4. Enter Event ID: `7045`
5. Click OK

### PowerShell Method
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        ServiceName = ($xml.Event.EventData.Data | Where {$_.Name -eq 'ServiceName'}).'#text'
        ImagePath   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'ImagePath'}).'#text'
        StartType   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'StartType'}).'#text'
        AccountName = ($xml.Event.EventData.Data | Where {$_.Name -eq 'AccountName'}).'#text'
    }
} | Format-Table -AutoSize -Wrap
```

### Verify Service Was Installed
```powershell
Get-WmiObject Win32_Service | Where-Object {
    $_.Name -like "*Test*" -or $_.Name -like "*Attacker*" -or $_.Name -like "*WindowsUpdate*"
} | Select-Object Name, PathName, StartMode, State
```

---

## Cleanup After Lab

```powershell
sc.exe delete "TestService7045"
sc.exe delete "AttackerService"
sc.exe delete "WindowsUpdateHelper"
```

---

## SOC Analyst Notes

### What to Look For

| Indicator | Risk |
|-----------|------|
| Binary path points to `%TEMP%`, `%APPDATA%`, `C:\Users\Public` | 🔴 Malware |
| Service name mimics a legitimate Windows service | 🔴 Masquerading |
| Service installed by a non-admin user | 🔴 Investigate immediately |
| Service account is `LocalSystem` with unusual binary | 🔴 High privilege malware |
| Service installed outside business hours | 🟡 Suspicious |
| Start type is `Automatic` for an unknown service | 🔴 Persistence mechanism |

### Attack Scenario

```
Attacker gets initial access
    → Drops payload.exe to C:\Users\Public\
    → Runs: sc.exe create "WinUpdate" binPath= "C:\Users\Public\payload.exe" start= auto
    → Event 7045 fires in System log
    → Service survives every reboot automatically
    → Analyst catches it by checking ImagePath in 7045 events
```

### Related Events

| Event ID | Log | Relationship |
|----------|-----|-------------|
| 4697 | Security | Same installation — Security log version |
| 7036 | System | Service started after installation |
| 7040 | System | Start type changed after installation |
| 4688 | Security | Process created when service runs |
