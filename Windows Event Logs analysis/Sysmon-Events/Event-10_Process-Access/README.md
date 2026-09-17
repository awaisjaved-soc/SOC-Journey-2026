# Sysmon Event ID 10 – Process Access

## Overview

| Field        | Details                              |
|--------------|--------------------------------------|
| **Event ID** | 10                                   |
| **Category** | Process & System Events              |
| **Name**     | Process Access                       |
| **Log**      | Microsoft-Windows-Sysmon/Operational |
| **Importance** | Critical                           |

---

## What Is Event ID 10?

**Event ID 10 (Process Access)** is generated when one process opens another process and requests access rights to it.

In simple terms: when **Process A** tries to look inside or control **Process B**, Sysmon records it as Event ID 10.

This is one of the most important Sysmon events for SOC analysts because many real attacks — especially **credential dumping** — require a process to open the memory of sensitive system processes like `lsass.exe`.

Tools such as Mimikatz, ProcDump, and other credential stealers all generate Event ID 10 because they need to open `lsass.exe` to read its memory and extract password hashes.

This event helps detect:
- Credential dumping attacks (Mimikatz, ProcDump, etc.)
- Process injection attempts
- Suspicious tools opening sensitive system processes
- Unauthorized memory access

---

## Key Fields

| Field            | Meaning                                                    |
|------------------|------------------------------------------------------------|
| `SourceImage`    | The process that is requesting access to another process   |
| `TargetImage`    | The process being accessed / opened                        |
| `GrantedAccess`  | The permissions that were granted (as a hex value)         |
| `SourceUser`     | User account that ran the source process                   |
| `TargetUser`     | User context of the target process                         |
| `CallTrace`      | Stack trace showing how the access was requested           |

**Most important target to watch:** `C:\Windows\System32\lsass.exe`

---

## Understanding GrantedAccess Values

The `GrantedAccess` value is a hex bitmask. High-risk access values include:

| Value    | Meaning                                         | Risk     |
|----------|-------------------------------------------------|----------|
| `0x1010` | Read control + process query information        | High     |
| `0x1400` | Read control + process query limited info       | Medium   |
| `0x1478` | Common Mimikatz access mask for LSASS           | Critical |
| `0x2000` | Process query limited information               | Low      |

Values commonly seen in the lab from normal `Explorer.exe` activity (`0x2000`) are low-risk. High values involving LSASS from unusual processes are critical.

---

## Why Event ID 10 Is Noisy

Many legitimate Windows activities also open other processes, so this event floods quickly when enabled without filtering:

- Task Manager viewing process details
- `Explorer.exe` querying other processes
- PowerShell `Get-Process` command
- Antivirus and EDR tools scanning processes
- Windows services (`svchost.exe`) managing other services

This is why in production SOC environments, Event ID 10 is usually filtered to only alert on access to high-value targets like `lsass.exe` from unexpected sources.

---

## How to Enable Event ID 10 (If Disabled)

Event ID 10 is often disabled or heavily filtered by default. To enable it:

```powershell
$config = @"
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessAccess onmatch="exclude">
    </ProcessAccess>
    <ProcessCreate onmatch="exclude">
    </ProcessCreate>
    <NetworkConnect onmatch="exclude">
    </NetworkConnect>
    <ImageLoad onmatch="exclude">
    </ImageLoad>
    <FileCreate onmatch="exclude">
    </FileCreate>
  </EventFiltering>
</Sysmon>
"@

$config | Out-File -FilePath "C:\SysmonConfig-Enable10.xml" -Encoding UTF8
```

```powershell
cd "C:\Sysmon"
.\Sysmon64.exe -c C:\SysmonConfig-Enable10.xml
```

---

## How to Generate Event ID 10 (Safe Methods)

### Method 1: PowerShell (Safe – Accesses LSASS as Admin)

```powershell
# PowerShell will open lsass.exe to read its information — this generates Event ID 10
Get-Process lsass | Format-List *

# Access explorer and winlogon too
Get-Process explorer | Format-List *
Get-Process winlogon | Out-Null
Get-Process | Select-Object -First 5
```

### Method 2: Task Manager

Open Task Manager → go to the **Details** tab → click on different processes. Task Manager opens each process to read its information, generating Event ID 10.

---

## Detection Commands

### Basic View

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=10]]" -MaxEvents 10 |
Select-Object TimeCreated, Id, Message | Format-List
```

### Detailed View

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=10]]" -MaxEvents 15 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time          = $_.TimeCreated
        SourceProcess = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SourceImage'}).'#text'
        TargetProcess = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetImage'}).'#text'
        GrantedAccess = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'GrantedAccess'}).'#text'
        SourceUser    = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SourceUser'}).'#text'
    }
} | Format-Table -AutoSize -Wrap
```

### High Priority Filter – LSASS Access Only

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=10]]" -MaxEvents 30 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    $target = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetImage'}).'#text'
    $source = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SourceImage'}).'#text'

    if ($target -like "*lsass.exe") {
        [PSCustomObject]@{
            Time          = $_.TimeCreated
            SourceProcess = $source
            TargetProcess = $target
            GrantedAccess = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'GrantedAccess'}).'#text'
            SourceUser    = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SourceUser'}).'#text'
        }
    }
} | Format-Table -AutoSize -Wrap
```

### Mark Interesting Events

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=10]]" -MaxEvents 20 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    $target = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetImage'}).'#text'
    $source = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SourceImage'}).'#text'

    [PSCustomObject]@{
        Time          = $_.TimeCreated
        SourceProcess = $source
        TargetProcess = $target
        Interesting   = if ($target -like "*lsass*") { "YES - LSASS ACCESS" } else { "No" }
    }
} | Format-Table -AutoSize -Wrap
```

---

## Lab Output Analysis

From the lab, the following Event ID 10 activity was observed:

| SourceProcess                  | TargetProcess                                                | GrantedAccess | Assessment |
|--------------------------------|--------------------------------------------------------------|---------------|------------|
| `C:\Windows\Explorer.EXE`      | `C:\Windows\system32\mmc.exe`                                | 0x2000        | Normal     |
| `C:\Windows\Explorer.EXE`      | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`  | 0x2000        | Normal     |
| `C:\Windows\Explorer.EXE`      | StartMenuExperienceHost.exe                                   | 0x2000        | Normal     |
| `C:\Windows\Explorer.EXE`      | SearchApp.exe                                                | 0x2000        | Normal     |
| `C:\Windows\system32\svchost.exe` | TextInputHost.exe                                         | 0x1000        | Normal     |

All observed activity was legitimate Windows desktop management. No suspicious LSASS access was detected, which is expected since no credential dumping tools were used.

---

## Real Attack Pattern (Concept)

What a Mimikatz-style credential dump would look like in Event ID 10:

```
SourceImage:   C:\Users\Public\m.exe        ← suspicious executable
TargetImage:   C:\Windows\System32\lsass.exe ← LSASS being accessed
GrantedAccess: 0x1478                         ← high-privilege memory read
SourceUser:    TECHCORP\Administrator
```

This combination — unknown process + LSASS target + high GrantedAccess — is one of the highest-priority alerts in any SOC.

---

## Normal vs Suspicious Activity

| Indicator          | Normal                                           | Suspicious                                              |
|--------------------|--------------------------------------------------|---------------------------------------------------------|
| **Source process** | `Explorer.exe`, `svchost.exe`, Task Manager      | Unknown `.exe`, processes from Temp/AppData/Downloads   |
| **Target process** | Other normal applications                        | `lsass.exe`, `winlogon.exe`, `csrss.exe`                |
| **GrantedAccess**  | `0x2000` (query info only)                       | `0x1478`, `0x1010` (memory read permissions)            |
| **Source path**    | `C:\Windows\System32\`                           | `C:\Temp\`, `C:\Users\Public\`, `AppData`               |

---

## SOC Analyst Notes

When analyzing Event ID 10:

1. **Always filter by target first.** LSASS, winlogon, and csrss are the highest-priority targets.
2. **Check the source process path.** A known system process accessing LSASS is normal. An unknown EXE from a user folder doing the same is critical.
3. **Check GrantedAccess values.** High-privilege access masks, especially ones that include memory read rights, are high-risk.
4. **Correlate with Event ID 1.** Find the matching process creation event for the suspicious source process. Where did it come from? What command line launched it?

---

## Key Takeaways

- Event ID 10 = One process opened another process
- Most events are normal Windows background activity (very noisy)
- Real detection value: unusual `SourceProcess` → `lsass.exe` with high `GrantedAccess`
- Always correlate: Source Process path + Target Process + GrantedAccess + User
- Pair with Event ID 1 to understand where the source process came from

---

*Lab environment: Windows Server 2022 – SOC Journey 2026*
