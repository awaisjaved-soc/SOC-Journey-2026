# Event ID 4656 — A Handle to an Object Was Requested

**Log:** Security  
**Category:** Object Access  
**Subcategory:** Handle Manipulation / Registry / File System  
**Level:** Information  
**Lab Environment:** Windows Server 2019 — TECHCORP / techcorp.local

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 4656 |
| Event Name | A handle to an object was requested |
| Log Location | Windows Logs → Security |
| Audit Category | Object Access |
| Audit Subcategory | Handle Manipulation |
| Default State | Disabled — must be manually enabled |
| Object Types | Registry Key, File, SAM, Kernel Object |

---

## What Is a Handle?

Before any program in Windows can read, write, or delete a registry key or file, it cannot access that object directly. It must first ask the Windows operating system for permission through a formal request. When the OS approves this request, it issues a numbered token called a **handle** — essentially a temporary access ticket. The program uses this handle for all subsequent operations on that object and releases it when done.

Think of it exactly like a hotel key card system. You cannot walk into any room you like. You go to the front desk, show your ID, and ask for Room 204. The receptionist checks if you are allowed in that room, then hands you a key card with a serial number. Every door you open with that card is logged. When you check out, you return the card. Event 4656 is the moment the receptionist hands over the key card and writes the entry in the hotel logbook — **before you have even walked to the room**.

---

## What Event 4656 Captures

Event 4656 fires at the exact moment a process calls the Windows API to open an object, before any actual read or write operation takes place. This makes it the **earliest possible warning signal** in the object access chain. The event records:

- Which object was requested (registry key path or file path)
- What type of access was requested (read, write, delete, full control, etc.)
- Which process made the request (process name and PID)
- Which user account owns that process
- A Handle ID that links this event to all subsequent 4663 and 4660 events on the same object

The access requested field is especially important. A process asking for READ access to a file is routine. A process asking for WRITE or DELETE access to a sensitive registry key like the Run key or SAM hive is immediately suspicious, regardless of whether the write actually happens — the intent is already recorded.

---

## What You Will See on Screen

**Nothing.** When you run the trigger commands, PowerShell will execute and return to the prompt. No window opens, no message appears, no confirmation is shown. This is correct and expected behaviour. The event fires invisibly at the kernel level. Your evidence is in the Security log, not on the desktop.

---

## Audit Policy Setup

### Method 1 — Group Policy (GUI)

1. Open **Group Policy Management** → right-click your domain or OU → **Edit**
2. Navigate to: `Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Object Access`
3. Double-click **Audit Handle Manipulation**
4. Check **Configure the following audit events**
5. Check **Success** and **Failure** → Apply → OK
6. Also enable **Audit Registry** and **Audit File System** under Object Access
7. Run `gpupdate /force` in an elevated command prompt

---


### Method 2 — Command Line (Recommended for Lab)

Open PowerShell or Command Prompt as Administrator:

```cmd
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
```

### Verify the Policy Is Active

```cmd
auditpol /get /subcategory:"Handle Manipulation"
auditpol /get /subcategory:"Registry"
```

Expected output should show `Success and Failure` for each subcategory.

---

## SACL Configuration — Required Step

Audit policy alone is not enough. You must also configure a **Security Access Control List (SACL)** on the specific object you want to audit. The SACL tells Windows which access types to log for that object.

### Configure SACL on the Run Registry Key (GUI)

1. Open **Registry Editor** (`regedit`) as Administrator
2. Navigate to: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
3. Right-click the `Run` key → **Permissions**
4. Click **Advanced** → select the **Auditing** tab
5. Click **Add** → **Select a principal** → type `Everyone` → OK
6. Set **Type** to `Success`
7. Set **Applies to** to `This key and subkeys`
8. Under Advanced permissions, check:
   - ✅ Query Value
   - ✅ Set Value
   - ✅ Create Subkey
   - ✅ Read Control
9. Click OK → Apply → OK all dialogs

---

<img width="728" height="390" alt="Screenshot_10" src="https://github.com/user-attachments/assets/e40b6f25-c869-4ad2-881d-3f00fd6b5d32" />


---

<img width="709" height="367" alt="Screenshot_8" src="https://github.com/user-attachments/assets/844a100e-e0c4-422e-8b28-a6e35db1c69c" />

---

<img width="598" height="360" alt="Screenshot_9" src="https://github.com/user-attachments/assets/d8e1fec9-dff8-45c5-a6cd-5333b6ed2072" />


---


## Generating the Event

### Method 1 — PowerShell (Recommended)

Open PowerShell as Administrator and run:

```powershell
# Request a handle to a sensitive registry key with write access
# This is exactly what malware does before modifying startup entries
$reg = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
    "SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    $true   # $true = request write access
)

Write-Host "Handle obtained. Check Security log for Event 4656."
Write-Host "Performing a read operation..."

# Read existing values through the handle
$names = $reg.GetValueNames()
foreach ($name in $names) {
    Write-Host "  Found: $name = $($reg.GetValue($name))"
}

# Release the handle — Windows will log the handle closure
$reg.Close()
Write-Host "Handle released."
```

---

<img width="798" height="457" alt="Screenshot_4" src="https://github.com/user-attachments/assets/8f060ba8-49aa-4552-8625-b646d0643ab7" />

---

<img width="614" height="427" alt="Screenshot_1" src="https://github.com/user-attachments/assets/aa629741-c896-4330-9829-65b160ce1542" />

---

<img width="742" height="434" alt="Screenshot_2" src="https://github.com/user-attachments/assets/b6fb566a-99c7-4c60-8037-8e328efd7449" />

---

<img width="871" height="461" alt="Screenshot_3" src="https://github.com/user-attachments/assets/64d8bc73-9eee-4293-ac42-736a9a433766" />

---


For a file handle request:

```powershell
# Request a handle to a sensitive system file
try {
    $stream = [System.IO.File]::Open(
        "C:\Windows\System32\drivers\etc\hosts",
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::ReadWrite
    )
    Write-Host "File handle obtained. Check Security log for Event 4656."
    $stream.Close()
} catch {
    Write-Host "Access denied (expected for restricted files) — 4656 with Failure still fires"
}
```

### Method 2 — GUI Trigger

1. Open **Registry Editor** as Administrator
2. Navigate to: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
3. Simply navigating to and clicking on the key causes Windows to request a handle internally
4. For a more deliberate trigger: right-click any value → **Modify** → then cancel — the handle request still fires

---

## Detecting the Event

### Method 1 — Event Viewer (GUI)

1. Open **Event Viewer** → **Windows Logs** → **Security**
2. Click **Filter Current Log** in the right panel
3. In the **Event ID** field enter: `4656`
4. Click OK
5. Look for entries timestamped when you ran your trigger commands
6. Double-click an event to open the details pane

**Key fields to examine in the event details:**

| Field | What to Look For |
|---|---|
| Subject: Account Name | Which user account triggered the request |
| Subject: Logon ID | Cross-reference with logon events |
| Object Type | `Key` for registry, `File` for files |
| Object Name | Full path — e.g. `\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| Access Requested | What the process wanted — READ_CONTROL, WRITE_DAC, Set Value, etc. |
| Process Name | Which executable made the request — `powershell.exe`, `regedit.exe`, etc. |
| Process ID | Hex PID to cross-reference with 4688 process creation events |
| Handle ID | Critical — use this to link to subsequent 4663 and 4660 events |
| Transaction ID | Groups related operations together |


---

<img width="808" height="436" alt="Screenshot_5" src="https://github.com/user-attachments/assets/8b955663-269e-4b1c-9e69-1f495eee0fda" />

---

<img width="635" height="436" alt="Screenshot_6" src="https://github.com/user-attachments/assets/0b2a07a6-7e02-4835-a273-07f1269f1895" />

---


<img width="635" height="434" alt="Screenshot_7" src="https://github.com/user-attachments/assets/b2b5b207-98dd-4719-b4d3-797ea9222a36" />

---


### Method 2 — PowerShell Detection

```powershell
# Query Security log for all 4656 events in the last hour
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4656
    StartTime = (Get-Date).AddHours(-1)
} | Select-Object TimeCreated, Message | Format-List
```

```powershell
# Filter specifically for Run key access attempts
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4656
    StartTime = (Get-Date).AddHours(-1)
} | Where-Object {
    $_.Message -like "*CurrentVersion\Run*"
} | Format-List TimeCreated, Message
```
---

<img width="673" height="387" alt="Screenshot_3sa" src="https://github.com/user-attachments/assets/739f9a9b-2289-421a-834c-0b5dbcb2cf8e" />

---

```powershell
# XML query for precise field extraction — shows object name and process
$filter = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[EventID=4656] and
        EventData[Data[@Name='ObjectName'] and contains(Data,'CurrentVersion\Run')]]
    </Select>
  </Query>
</QueryList>
"@

Get-WinEvent -FilterXml $filter | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        AccountName = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        ObjectName  = ($data | Where-Object { $_.Name -eq 'ObjectName'      }).'#text'
        AccessMask  = ($data | Where-Object { $_.Name -eq 'AccessMask'      }).'#text'
        ProcessName = ($data | Where-Object { $_.Name -eq 'ProcessName'     }).'#text'
        HandleID    = ($data | Where-Object { $_.Name -eq 'HandleId'        }).'#text'
    }
} | Format-Table -AutoSize
```

---

<img width="947" height="482" alt="asd" src="https://github.com/user-attachments/assets/24cc480a-37d4-4c6d-9552-8d18f09c31fb" />

---


```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          9/3/2026 1:57:41 AM
Event ID:      4656
Task Category: Registry
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-LFHCJK09RND.techcorp.local
Description:
A handle to an object was requested.

Subject:
	Security ID:		TECHCORP\administrator
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x2970A4

Object:
	Object Server:		Security
	Object Type:		Key
	Object Name:		\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	Handle ID:		0x350
	Resource Attributes:	-

Process Information:
	Process ID:		0xcf0
	Process Name:		C:\Windows\regedit.exe

Access Request Information:
	Transaction ID:		{00000000-0000-0000-0000-000000000000}
	Accesses:		DELETE
				READ_CONTROL
				WRITE_DAC
				WRITE_OWNER
				Query key value
				Set key value
				Create sub-key
				Enumerate sub-keys
				Notify about changes to keys
				Create Link
				
	Access Reasons:		-
	Access Mask:		0xF003F
	Privileges Used for Access Check:	-
	Restricted SID Count:	0
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4656</EventID>
    <Version>1</Version>
    <Level>0</Level>
    <Task>12801</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-03T08:57:41.3155657Z" />
    <EventRecordID>15157</EventRecordID>
    <Correlation />
    <Execution ProcessID="4" ThreadID="7412" />
    <Channel>Security</Channel>
    <Computer>WIN-LFHCJK09RND.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-2393829360-1893506578-1941953886-500</Data>
    <Data Name="SubjectUserName">administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x2970a4</Data>
    <Data Name="ObjectServer">Security</Data>
    <Data Name="ObjectType">Key</Data>
    <Data Name="ObjectName">\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</Data>
    <Data Name="HandleId">0x350</Data>
    <Data Name="TransactionId">{00000000-0000-0000-0000-000000000000}</Data>
    <Data Name="AccessList">%%1537
				%%1538
				%%1539
				%%1540
				%%4432
				%%4433
				%%4434
				%%4435
				%%4436
				%%4437
				</Data>
    <Data Name="AccessReason">-</Data>
    <Data Name="AccessMask">0xf003f</Data>
    <Data Name="PrivilegeList">-</Data>
    <Data Name="RestrictedSidCount">0</Data>
    <Data Name="ProcessId">0xcf0</Data>
    <Data Name="ProcessName">C:\Windows\regedit.exe</Data>
    <Data Name="ResourceAttributes">-</Data>
  </EventData>
</Event>
```

---


## SOC Analyst Notes

### Normal vs Suspicious

| Scenario | Verdict |
|---|---|
| `svchost.exe` requesting read handle to registry keys during boot | Normal — Windows services initialising |
| `regedit.exe` requesting handle — user is Administrator | Normal — admin managing registry |
| `powershell.exe` requesting WRITE handle to `HKLM\...\Run` at 3 AM | **Suspicious — investigate** |
| Unknown process requesting DELETE handle to a log file | **Critical alert** |
| Any process requesting handle to `HKLM\SECURITY` or `HKLM\SAM` | **Critical — credential access attempt** |

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Known system processes, read-only access, business hours |
| 🟡 Medium | PowerShell requesting write access, unusual hours |
| 🔴 High | Unknown process, write/delete to Run key, SAM, or SECURITY hive |
| 🔴 Critical | Any access to SAM hive from non-system process |

### Correlation with Other Events

4656 is most powerful when correlated with:
- **4663** — shows what the process actually did with the handle
- **4657** — shows the specific registry value that was modified
- **4660** — shows if the object was deleted through this handle
- **4688** — shows when the process that triggered 4656 was originally created

The **Handle ID** is the thread that links all these events together. Always note the Handle ID from 4656 and search for matching Handle IDs in 4663 and 4660 events.

### MITRE ATT&CK Reference

- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys
- **T1012** — Query Registry
- **T1552.002** — Unsecured Credentials: Credentials in Registry
