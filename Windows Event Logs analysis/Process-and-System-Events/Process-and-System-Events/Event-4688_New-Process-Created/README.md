# Event 4688 – A New Process Was Created

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4688 |
| **Category** | Process & System Events |
| **Log** | Security |
| **Tier** | 🔴 Tier 1 – Critical |
| **SOC Importance** | 🔴 Very High |

## What Is This Event?

Event 4688 is generated every time a **new process starts** on the system. It records the process name, command line arguments, parent process, the user who launched it, and the process ID.

This is one of the most critical events in a SOC environment because **almost every malware, living-off-the-land binary (LOLBin), and attacker tool creates a process**. By analyzing parent-child process relationships, analysts can detect suspicious execution chains before damage occurs.

---

## Setup – Must Do First

Run these commands as **Administrator** before generating or detecting this event:

```powershell
# Step 1 – Enable Process Creation Auditing
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Step 2 – Enable Command Line Logging in Process Creation (Very Important)
# Without this, the CommandLine field will be empty in the event
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Step 3 – Apply policy
gpupdate /force
```

> **Why Step 2 matters:** Without enabling command line logging, Event 4688 will show the process name but the `CommandLine` field will be blank — making it nearly useless for detecting attacks.

### Verify the Policy is Active

```powershell
auditpol /get /subcategory:"Process Creation"
```

Expected output: `Process Creation   Success and Failure`

---

## How to Generate This Event

### Method 1 – Manual GUI
1. Open any program — Notepad, Calculator, cmd.exe, Chrome
2. Event 4688 is automatically generated for every program that starts

### Method 2 – PowerShell
```powershell
Start-Process notepad.exe
Start-Process calc.exe
Start-Process cmd.exe
```

---

## Detection Commands

### Basic Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 10 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time          = $_.TimeCreated
        NewProcess    = ($xml.Event.EventData.Data | Where {$_.Name -eq 'NewProcessName'}).'#text'
        CommandLine   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'CommandLine'}).'#text'
        ParentProcess = ($xml.Event.EventData.Data | Where {$_.Name -eq 'ParentProcessName'}).'#text'
        User          = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
    }
} | Format-Table -AutoSize -Wrap
```

### Extended Detection – Includes Token Elevation Type
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 15 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time            = $_.TimeCreated
        Process         = ($xml.Event.EventData.Data | Where {$_.Name -eq 'NewProcessName'}).'#text'
        CommandLine     = ($xml.Event.EventData.Data | Where {$_.Name -eq 'CommandLine'}).'#text'
        ParentProcess   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'ParentProcessName'}).'#text'
        TokenElevation  = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TokenElevationType'}).'#text'
        User            = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
    }
} | Format-Table -AutoSize -Wrap
```

---

## Token Elevation Types – Full Lab

Event 4688 includes a `TokenElevationType` field which tells you the privilege level of the process. This is critical for detecting privilege escalation.

### Token Elevation Reference Table

| Type | Value in Event | Name | When It Happens |
|------|---------------|------|-----------------|
| 1 | `%%1936` | Full Token | Built-in Administrator account or UAC disabled |
| 2 | `%%1937` | Elevated Token | User clicked "Run as Administrator" (UAC prompt) |
| 3 | `%%1938` | Limited Token | Normal process under standard UAC — most common |

---

### Lab – Generate All 3 Token Types

#### Type 3 – Limited Token (Most Common)
Run any program normally — no elevation:
```powershell
Start-Process notepad.exe
Start-Process calc.exe
```
Result: `TokenElevationType = %%1938`

---

#### Type 2 – Elevated Token (Run as Administrator)
```powershell
Start-Process notepad.exe -Verb RunAs
```
Or: Right-click any program → **Run as administrator**

Result: `TokenElevationType = %%1937`

---

#### Type 1 – Full Token (Built-in Administrator)
This only occurs when:
- Logged in as the **built-in Administrator** account (not a domain admin)
- Or UAC is completely disabled

```powershell
# Log in as built-in Administrator, then run:
Start-Process notepad.exe
```
Result: `TokenElevationType = %%1936`

> **Lab Note:** If you are already logged in as the built-in Administrator and only see Type 1, that is expected and correct. To generate Type 2 and Type 3, you need to switch to a normal domain user like `alexrivera`.

---

### Prepare alexrivera for Token Elevation Lab

On a **Domain Controller**, `Add-LocalGroupMember` sometimes fails. Use these commands instead:

```powershell
# Method 1 – net command (most reliable on DC)
net localgroup Administrators alexrivera /add

# Method 2 – AD PowerShell
Add-ADGroupMember -Identity "Administrators" -Members "alexrivera"

# Method 3 – Combined fallback
Add-LocalGroupMember -Group "Administrators" -Member "alexrivera" -ErrorAction SilentlyContinue
net localgroup "Administrators" alexrivera /add
```

Verify the user was added:
```powershell
net localgroup Administrators
```

Then:
- Log in as `alexrivera` → Open Notepad normally → **Type 3**
- Log in as `alexrivera` → Right-click Notepad → Run as administrator → **Type 2**
- Log in as built-in `Administrator` → Open Notepad → **Type 1**

---

## SOC Analyst Notes

### What to Look For

| Indicator | Risk |
|-----------|------|
| `cmd.exe` or `powershell.exe` spawned by `word.exe` or `excel.exe` | 🔴 Macro-based malware |
| `mshta.exe`, `wscript.exe`, `cscript.exe` with unusual parents | 🔴 Script-based attack |
| Base64 encoded strings in CommandLine | 🔴 Obfuscated PowerShell |
| Process spawned from `%TEMP%` or `%APPDATA%` | 🔴 Malware dropper |
| `net.exe`, `whoami.exe`, `ipconfig.exe` in quick succession | 🟡 Reconnaissance activity |
| Token Type 2 from a non-admin account | 🟡 Privilege escalation attempt |

### Dangerous Process Chains to Monitor

```
word.exe → cmd.exe              (macro malware)
excel.exe → powershell.exe      (macro malware)
explorer.exe → mshta.exe        (living off the land)
powershell.exe → net.exe        (lateral movement recon)
svchost.exe → cmd.exe           (suspicious service behavior)
```

### Common LOLBins That Appear in 4688

| Binary | Abuse Method |
|--------|-------------|
| `mshta.exe` | Execute remote HTA scripts |
| `certutil.exe` | Download files, decode base64 |
| `bitsadmin.exe` | Download payloads |
| `regsvr32.exe` | Execute remote DLLs |
| `rundll32.exe` | Execute code from DLLs |
| `wmic.exe` | Remote execution, recon |
