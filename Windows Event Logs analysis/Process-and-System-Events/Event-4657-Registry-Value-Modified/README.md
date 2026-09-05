# Event ID 4657 — A Registry Value Was Modified

**Log:** Security  
**Category:** Object Access  
**Subcategory:** Registry  
**Level:** Information  
**Lab Environment:** Windows Server 2019 — TECHCORP / techcorp.local

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 4657 |
| Event Name | A registry value was modified |
| Log Location | Windows Logs → Security |
| Audit Category | Object Access |
| Audit Subcategory | Registry |
| Default State | Disabled — requires both audit policy AND SACL configuration |
| Object Types | Registry Key Values only |

---

## What Is Event 4657?

Event 4657 is one of the most forensically valuable events in the entire Windows Security log. It fires whenever a registry value is created, modified, or deleted — but only when the containing key has been configured with a SACL that includes **Set Value** in the auditing permissions.

What makes 4657 uniquely powerful is that it records **both the old value and the new value** at the moment of change. This means you can see exactly what a registry entry looked like before an attacker modified it, and exactly what they changed it to. No other Windows event provides this before-and-after record for registry modifications.

---

## Why the Run Key Matters

The Windows Run key is one of the most abused registry locations in the history of malware:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

Every value stored under this key is treated by Windows as a startup program. On every user logon, Windows reads through the Run key and launches every program listed there. Malware that writes itself into this key survives reboots and persists on the system indefinitely — until the entry is removed.

This technique is called **registry-based persistence** and it has been used by virtually every major malware family in the last two decades. Event 4657 is your primary detection mechanism for this entire class of attack.

When you triggered 4657 in the lab by writing `C:\Temp\malware_sim.exe` to `SOCLabTest` in the Run key, you were performing exactly the same operation that ransomware, banking trojans, RATs, and APT implants perform when establishing persistence on a victim machine.

---

## Why 4657 Is Harder to Enable Than Other Events

Most events in earlier tiers only required enabling an audit policy. Event 4657 requires two completely separate configurations that must both be correct simultaneously:

**Requirement 1 — Audit Policy:** The Registry subcategory under Object Access must be enabled for Success events.

**Requirement 2 — SACL on the Key:** The specific registry key you want to monitor must have an auditing entry that includes **Set Value**. If the SACL is missing, or if it only has Read Control checked (a common mistake), 4657 will never fire regardless of the audit policy.

This is the most common reason 4657 fails in lab environments. The SACL must explicitly include Set Value permission in the auditing entry.

---

## What You Will See on Screen

Nothing. `Set-ItemProperty` will execute silently and return to the prompt. If you open Registry Editor and navigate to the Run key, you will see your new value listed there. But the 4657 event fires in the background at the kernel level with no visual indication. Go directly to Event Viewer to find your evidence.

---

## Audit Policy Setup

### Method 1 — Group Policy (GUI)

1. Open **Group Policy Management** → right-click your domain → **Edit**
2. Navigate to: `Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Object Access`
3. Double-click **Audit Registry**
4. Check **Configure the following audit events** → check **Success** → OK
5. Run `gpupdate /force`


### Method 2 — Command Line (Recommended for Lab)

```cmd
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
```

Verify:

```cmd
auditpol /get /subcategory:"Registry"
```

Expected output: `Registry    Success and Failure`

---

## SACL Configuration — Critical Step

This step is what most people miss. Without the correct SACL, 4657 will never fire.

### Configure SACL on the Run Key (GUI)

1. Open **Registry Editor** (`regedit`) as Administrator
2. Navigate to: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
3. Right-click `Run` → **Permissions** → **Advanced**
4. Click the **Auditing** tab
5. Click **Add** → **Select a principal** → type `Everyone` → click OK
6. Set **Type** to `Success`
7. Set **Applies to** to `This key and subkeys`
8. Click **Show advanced permissions**
9. Check the following boxes:
   - ✅ **Set Value** ← this is the critical one for 4657
   - ✅ **Create Subkey**
   - ✅ **Query Value**
10. Click OK → Apply → OK all dialogs

> **Important:** If you only check Read Control, you will get 4656 events but never 4657. Set Value must be explicitly checked.

---


<img width="679" height="385" alt="Screenshot_2" src="https://github.com/user-attachments/assets/c8d1bc9e-df4d-4018-81d3-7ea83bc70a62" />

---


## Generating the Event

### Method 1 — PowerShell (Recommended)

Open PowerShell as Administrator:

```powershell
# Step 1: Remove any previous test entry to start clean
Remove-ItemProperty `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name "SOCLabTest" `
    -ErrorAction SilentlyContinue

# Step 2: Create the entry with an initial value (simulates malware first installation)
Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name "SOCLabTest" `
    -Value "C:\Windows\System32\notepad.exe"

Write-Host "Entry created. Now modifying to simulate malware update..."

# Step 3: Modify the value — this is the line that fires Event 4657
# The kernel detects the Set Value operation, checks the SACL, and logs the change
Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name "SOCLabTest" `
    -Value "C:\Temp\malware_sim.exe"

Write-Host "Value modified. Check Security log for Event ID 4657."
Write-Host "You should see OldValue: notepad.exe and NewValue: malware_sim.exe"
```
---

<img width="471" height="329" alt="Screenshot_1" src="https://github.com/user-attachments/assets/4f209b79-ddb4-4600-b182-6cec86c619e6" />

---

<img width="639" height="435" alt="Screenshot_11" src="https://github.com/user-attachments/assets/35611bff-3d8c-48c6-acd5-a49da2fe5dfa" />

---


For creating a brand new value (also triggers 4657 with Operation Type = New value created):

```powershell
# Create a completely new Run key entry
New-ItemProperty `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name "PersistenceTest" `
    -Value "C:\Users\Public\payload.exe" `
    -PropertyType String `
    -Force

Write-Host "New value created — check for 4657 with operation type New value"
```

Cleanup after lab:

```powershell
Remove-ItemProperty `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name "SOCLabTest" `
    -ErrorAction SilentlyContinue

Remove-ItemProperty `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name "PersistenceTest" `
    -ErrorAction SilentlyContinue

Write-Host "Test entries removed."
```

### Method 2 — GUI Trigger

1. Open **Registry Editor** as Administrator
2. Navigate to: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
3. Right-click in the right panel → **New** → **String Value**
4. Name it `SOCLabGUITest`
5. Double-click it → set value to `C:\Temp\malware_gui.exe` → OK
6. To trigger a modification: double-click the value again → change it → OK

---

## Detecting the Event

### Method 1 — Event Viewer (GUI)

1. Open **Event Viewer** → **Windows Logs** → **Security**
2. Click **Filter Current Log**
3. Enter Event ID: `4657` → OK
4. Locate events timestamped when you ran your trigger commands
5. Double-click to open details

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Subject: Account Name | Who made the modification |
| Object Name | Full registry path of the key |
| Object Value Name | The specific value that was changed — e.g. `SOCLabTest` |
| Old Value | What the value contained before the modification |
| New Value | What the value was changed to |
| Old Value Type | Data type before (REG_SZ, REG_DWORD, etc.) |
| New Value Type | Data type after |
| Operation Type | `%%1904` = New value created / `%%1905` = Existing value modified / `%%1906` = Value deleted |
| Process Name | Which executable made the change |
| Subject: Logon ID | Links to the logon session |

### Method 2 — PowerShell Detection

```powershell
# Find all 4657 events in the last hour
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4657
    StartTime = (Get-Date).AddHours(-1)
} | Select-Object TimeCreated, Message | Format-List
```
---

<img width="956" height="468" alt="as" src="https://github.com/user-attachments/assets/f406bf52-a359-416b-8b2e-a6e39a2cbdd3" />

---


```powershell
# Advanced XML query — extracts key fields for analysis
$filter = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[EventID=4657]]
    </Select>
  </Query>
</QueryList>
"@

Get-WinEvent -FilterXml $filter | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time           = $_.TimeCreated
        AccountName    = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        ObjectName     = ($data | Where-Object { $_.Name -eq 'ObjectName'      }).'#text'
        ValueName      = ($data | Where-Object { $_.Name -eq 'ObjectValueName' }).'#text'
        OldValue       = ($data | Where-Object { $_.Name -eq 'OldValue'        }).'#text'
        NewValue       = ($data | Where-Object { $_.Name -eq 'NewValue'        }).'#text'
        OperationType  = ($data | Where-Object { $_.Name -eq 'OperationType'   }).'#text'
        ProcessName    = ($data | Where-Object { $_.Name -eq 'ProcessName'     }).'#text'
    }
} | Format-Table -AutoSize
```

```powershell
# Hunt specifically for Run key modifications — high priority
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4657
    StartTime = (Get-Date).AddDays(-1)
} | Where-Object {
    $_.Message -like "*CurrentVersion\Run*"
} | ForEach-Object {
    Write-Host "=== RUN KEY MODIFICATION DETECTED ===" -ForegroundColor Red
    Write-Host "Time: $($_.TimeCreated)"
    Write-Host $_.Message
}
```

---

```powwershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          9/3/2026 2:14:26 AM
Event ID:      4657
Task Category: Registry
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-LFHCJK09RND.techcorp.local
Description:
A registry value was modified.

Subject:
	Security ID:		TECHCORP\administrator
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x2970A4

Object:
	Object Name:		\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	Object Value Name:	SOCLabTest
	Handle ID:		0xd84
	Operation Type:		Existing registry value modified

Process Information:
	Process ID:		0x1fb0
	Process Name:		C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Change Information:
	Old Value Type:		REG_SZ
	Old Value:		C:\Windows\System32\notepad.exe
	New Value Type:		REG_SZ
	New Value:		C:\Temp\malware_sim.exe
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4657</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12801</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-03T09:14:26.8908099Z" />
    <EventRecordID>17212</EventRecordID>
    <Correlation />
    <Execution ProcessID="4" ThreadID="5484" />
    <Channel>Security</Channel>
    <Computer>WIN-LFHCJK09RND.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-2393829360-1893506578-1941953886-500</Data>
    <Data Name="SubjectUserName">administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x2970a4</Data>
    <Data Name="ObjectName">\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</Data>
    <Data Name="ObjectValueName">SOCLabTest</Data>
    <Data Name="HandleId">0xd84</Data>
    <Data Name="OperationType">%%1905</Data>
    <Data Name="OldValueType">%%1873</Data>
    <Data Name="OldValue">C:\Windows\System32\notepad.exe</Data>
    <Data Name="NewValueType">%%1873</Data>
    <Data Name="NewValue">C:\Temp\malware_sim.exe</Data>
    <Data Name="ProcessId">0x1fb0</Data>
    <Data Name="ProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
  </EventData>
</Event>
```

---


## SOC Analyst Notes

### Operation Type Codes

| Code | Meaning |
|---|---|
| `%%1904` | A new value was created |
| `%%1905` | An existing value was modified |
| `%%1906` | A value was deleted |

### High-Value Registry Locations to Monitor with 4657

| Registry Path | Why It Matters |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | System-wide startup programs |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Per-user startup programs |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | Run once at next boot |
| `HKLM\SYSTEM\CurrentControlSet\Services` | Service configurations |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | Logon process manipulation |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | LSA security settings |

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Known installer writing to Run key during software setup |
| 🟡 Medium | PowerShell modifying Run key during business hours |
| 🔴 High | Unknown process writing to Run key after hours |
| 🔴 Critical | Any modification to LSA, Winlogon, or Services keys from non-system process |

### MITRE ATT&CK Reference

- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1112** — Modify Registry
- **T1543.003** — Create or Modify System Process: Windows Service
