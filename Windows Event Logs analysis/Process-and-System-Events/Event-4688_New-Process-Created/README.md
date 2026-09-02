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

---

<img width="468" height="328" alt="Screenshot_1" src="https://github.com/user-attachments/assets/5715f3fd-0053-4bc4-ad45-7c8ce49ee860" />


---

<img width="465" height="329" alt="Screenshot_2" src="https://github.com/user-attachments/assets/677a6b73-6108-4e96-8f30-98b33f9a9cdb" />

---

### Method 2 – PowerShell
```powershell
Start-Process notepad.exe
Start-Process calc.exe
Start-Process cmd.exe
```



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

---

<img width="391" height="263" alt="type3demo" src="https://github.com/user-attachments/assets/79e80c46-3344-458e-a82d-2fd05468b0c6" />

---

<img width="465" height="330" alt="type3" src="https://github.com/user-attachments/assets/4b1dce29-ec24-4b7e-9cbe-c94b80842081" />

---

<img width="668" height="368" alt="detection" src="https://github.com/user-attachments/assets/33c15fcc-e5de-4df6-86b2-8e3fcf53e1d2" />

---

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

<img width="391" height="263" alt="type3demo" src="https://github.com/user-attachments/assets/79e80c46-3344-458e-a82d-2fd05468b0c6" />

---

<img width="465" height="330" alt="type3" src="https://github.com/user-attachments/assets/4b1dce29-ec24-4b7e-9cbe-c94b80842081" />

---


#### Type 2 – Elevated Token (Run as Administrator)
```powershell
Start-Process notepad.exe -Verb RunAs
```
Or: Right-click any program → **Run as administrator**

Result: `TokenElevationType = %%1937`

---

<img width="384" height="264" alt="type2demo" src="https://github.com/user-attachments/assets/53238af9-f5a1-4ce4-aee0-8672d72cce50" />

---

<img width="621" height="421" alt="type2alex" src="https://github.com/user-attachments/assets/d0bdf436-7227-4ffc-961c-46b2b81e8c13" />

---


<img width="609" height="302" alt="type2" src="https://github.com/user-attachments/assets/c4d7bf4b-f439-4645-8dda-b985e33a8118" />


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


---

<img width="468" height="328" alt="Screenshot_1" src="https://github.com/user-attachments/assets/e81a4d8e-8814-420f-97d7-713140fb7a1f" />

---


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

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          9/2/2026 7:47:55 PM
Event ID:      4688
Task Category: Process Creation
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-LFHCJK09RND.techcorp.local
Description:
A new process has been created.

Creator Subject:
	Security ID:		TECHCORP\administrator
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x57D34

Target Subject:
	Security ID:		NULL SID
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Process Information:
	New Process ID:		0x1200
	New Process Name:	C:\Program Files\Google\Chrome\Application\chrome.exe
	Token Elevation Type:	TokenElevationTypeDefault (1)
	Mandatory Label:		Mandatory Label\High Mandatory Level
	Creator Process ID:	0x91c
	Creator Process Name:	C:\Program Files\Google\Chrome\Application\chrome.exe
	Process Command Line:	"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=utility --utility-sub-type=chrome.mojom.ProcessorMetrics --lang=en-US --service-sandbox-type=none --metrics-shmem-handle=5640,i,15874126210861576485,7353365318987223055,524288 --field-trial-handle=1916,i,8162570589214045527,10936867941413330473,262144 --variations-seed-version=20260725-030027.786000-production --pseudonymization-salt-handle=1928,i,14450796533579535610,13635666912291948844,4 --trace-process-track-uuid=3190708995682289984 --mojo-platform-channel-handle=5608 /prefetch:8

Token Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.

Type 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.

Type 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.

Type 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator.
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4688</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>13312</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-03T02:47:55.3597242Z" />
    <EventRecordID>8966</EventRecordID>
    <Correlation />
    <Execution ProcessID="4" ThreadID="4808" />
    <Channel>Security</Channel>
    <Computer>WIN-LFHCJK09RND.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-2393829360-1893506578-1941953886-500</Data>
    <Data Name="SubjectUserName">administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x57d34</Data>
    <Data Name="NewProcessId">0x1200</Data>
    <Data Name="NewProcessName">C:\Program Files\Google\Chrome\Application\chrome.exe</Data>
    <Data Name="TokenElevationType">%%1936</Data>
    <Data Name="ProcessId">0x91c</Data>
    <Data Name="CommandLine">"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=utility --utility-sub-type=chrome.mojom.ProcessorMetrics --lang=en-US --service-sandbox-type=none --metrics-shmem-handle=5640,i,15874126210861576485,7353365318987223055,524288 --field-trial-handle=1916,i,8162570589214045527,10936867941413330473,262144 --variations-seed-version=20260725-030027.786000-production --pseudonymization-salt-handle=1928,i,14450796533579535610,13635666912291948844,4 --trace-process-track-uuid=3190708995682289984 --mojo-platform-channel-handle=5608 /prefetch:8</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">-</Data>
    <Data Name="TargetDomainName">-</Data>
    <Data Name="TargetLogonId">0x0</Data>
    <Data Name="ParentProcessName">C:\Program Files\Google\Chrome\Application\chrome.exe</Data>
    <Data Name="MandatoryLabel">S-1-16-12288</Data>
  </EventData>
</Event>
```

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
