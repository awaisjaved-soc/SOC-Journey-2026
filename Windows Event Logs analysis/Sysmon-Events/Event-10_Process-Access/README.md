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


<img width="470" height="329" alt="Screenshot_6" src="https://github.com/user-attachments/assets/8b0fb270-d953-4cce-8d1c-d0dcf73fa12a" />

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
---

<img width="420" height="296" alt="Screenshot_2" src="https://github.com/user-attachments/assets/485d9166-add4-45b1-bfcc-b55f61e60892" />

---


```powershell
cd "C:\Sysmon"
.\Sysmon64.exe -c C:\SysmonConfig-Enable10.xml
```

---

<img width="637" height="284" alt="Screenshot_1" src="https://github.com/user-attachments/assets/bc0fed1c-21eb-4670-9afe-80b940bfda80" />

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

---

<img width="655" height="432" alt="Screenshot_5" src="https://github.com/user-attachments/assets/a9f5fffc-e6d4-4a46-945b-3703ba1dbb62" />

---

<img width="609" height="288" alt="Screenshot_4" src="https://github.com/user-attachments/assets/1d57ac66-e372-4d82-a35b-5da5547f4e96" />

---

<img width="605" height="284" alt="Screenshot_3" src="https://github.com/user-attachments/assets/81e2972a-0736-46ec-ab6f-d9f9edc5fcfc" />

---

<img width="470" height="329" alt="Screenshot_6" src="https://github.com/user-attachments/assets/4296940e-5474-4157-bb48-6bfa936baa98" />

---


### Method 2: Task Manager

Open Task Manager → go to the **Details** tab → click on different processes. Task Manager opens each process to read its information, generating Event ID 10.

---

## Detection Commands

### Basic View

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=10]]" -MaxEvents 10 |
Select-Object TimeCreated, Id, Message | Format-List
```
---

<img width="470" height="330" alt="Screenshot_7" src="https://github.com/user-attachments/assets/559f0399-a544-48bc-9ea2-e80309d5a250" />

---

<img width="960" height="313" alt="Screenshot_8" src="https://github.com/user-attachments/assets/346b1c9d-9e46-481f-84fb-5eecdc97ebfa" />

---


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
---


<img width="911" height="305" alt="Screenshot_9" src="https://github.com/user-attachments/assets/03d96dde-bcf3-43ee-a2d9-150c17610b69" />

---

<img width="946" height="441" alt="Screenshot_10" src="https://github.com/user-attachments/assets/3971dff0-e384-4d7d-83b2-800e6411bb90" />


---


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
---

<img width="947" height="462" alt="Screenshot_11" src="https://github.com/user-attachments/assets/04c69ddf-8adf-4bbc-93ff-37c51a499451" />

---


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
