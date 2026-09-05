# Event ID 4663 — An Attempt Was Made to Access an Object

**Log:** Security  
**Category:** Object Access  
**Subcategory:** Registry / File System  
**Level:** Information  
**Lab Environment:** Windows Server 2019 — TECHCORP / techcorp.local

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 4663 |
| Event Name | An attempt was made to access an object |
| Log Location | Windows Logs → Security |
| Audit Category | Object Access |
| Audit Subcategory | Registry, File System |
| Default State | Disabled — requires audit policy AND SACL configuration |
| Object Types | Registry Key, File, Directory, SAM, Active Directory objects |

---

## What Is Event 4663?

Event 4663 records the actual access operations performed on an audited object. While Event 4656 captures the moment a handle is requested (the intent to access), Event 4663 captures each specific operation that is performed through that handle (the actual access itself). This distinction is fundamental to understanding how Windows object access auditing works.

Every time a process reads a registry value, writes data to a file, enumerates subkeys, or attempts any other specific operation on an audited object, Windows generates a 4663 event recording exactly which operation was performed. A single handle request (4656) can be followed by many 4663 events if the process performs multiple operations through the same handle.

---

## 4656 vs 4663 — The Critical Distinction

This is the most commonly confused pair of events in Windows security auditing. Understanding the difference is essential for SOC work.

| | Event 4656 | Event 4663 |
|---|---|---|
| **When it fires** | When a process requests a handle | When a process uses the handle to perform an operation |
| **What it records** | "I want access to this object" | "I performed this specific operation on this object" |
| **Access information** | Requested permissions (what the process asked for) | Actual accesses performed (what the process did) |
| **Analogy** | Hotel guest asking for a room key | Hotel guest using the key to open the door, use the TV, open the safe |
| **Can you have multiple?** | Typically one per handle request | Yes — multiple 4663 events per 4656, one per operation |
| **Contains object name** | Yes | Yes |

The practical consequence is this: a process might request a handle with both read and write permissions (4656 shows both requested), but only ever read the data (4663 shows only read operations were performed). The 4663 events show you the truth of what actually happened, not just what the process intended to do.

---

## Access Type Codes in Event 4663

The Accesses field in 4663 uses numeric codes to identify the operation. These are the most common ones you will encounter:

| Access Code | Operation | Concern Level |
|---|---|---|
| `%%4416` | ReadData / Query Value | Low — reading data |
| `%%4417` | WriteData / Set Value | High — writing data |
| `%%4418` | AppendData / Create Subkey | High — creating new entries |
| `%%4419` | ReadExtendedAttributes | Low |
| `%%4420` | WriteExtendedAttributes | Medium |
| `%%4423` | Execute/Traverse | Low |
| `%%4424` | DeleteChild | High — deleting child objects |
| `%%4432` | Read attributes | Low |
| `%%4433` | Write attributes | Medium |
| `%%1537` | DELETE | Critical |
| `%%1538` | READ_CONTROL | Low |
| `%%1539` | WRITE_DAC | Critical — changing permissions |
| `%%1540` | WRITE_OWNER | Critical — changing ownership |

---

## What You Will See on Screen

Nothing. When you run the trigger commands, PowerShell will execute and return a value to the terminal — you will see the registry value printed on screen. But this is the PowerShell output, not a visual indicator of the 4663 event. The kernel-level audit record fires simultaneously but invisibly. Go to Event Viewer to see the 4663 entry.

---

## Audit Policy Setup

### Method 1 — Group Policy (GUI)

1. Open **Group Policy Management** → right-click domain → **Edit**
2. Navigate to: `Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Object Access`
3. Enable **Audit Registry** — Success and Failure
4. Enable **Audit File System** — Success and Failure
5. Run `gpupdate /force`

---

<img width="675" height="364" alt="Screenshot_1" src="https://github.com/user-attachments/assets/39df21a4-1f22-4da4-a888-332c79e3e463" />

---


### Method 2 — Command Line (Recommended for Lab)

```cmd
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
```

Verify:

```cmd
auditpol /get /subcategory:"Registry"
auditpol /get /subcategory:"File System"
```

---

## SACL Configuration

### Create Test Registry Key and Configure SACL

```powershell
# Create a dedicated test key for 4663 labs
New-Item -Path "HKLM:\SOFTWARE\SOCLabAudit" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\SOCLabAudit" `
    -Name "ConfidentialData" -Value "SensitiveValue123" -PropertyType String -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\SOCLabAudit" `
    -Name "AccessLevel" -Value "Administrator" -PropertyType String -Force

Write-Host "Test key created. Now configure auditing via regedit."
```

---

<img width="675" height="385" alt="Screenshot_2" src="https://github.com/user-attachments/assets/cf036f9f-1532-4b50-94f5-7375d2234b50" />

---


In Registry Editor:
1. Navigate to `HKLM:\SOFTWARE\SOCLabAudit`
2. Right-click → **Permissions** → **Advanced** → **Auditing** tab
3. Click **Add** → `Everyone` → OK
4. Type: `Success` | Applies to: `This key and subkeys`
5. Check the following permissions:
   - ✅ **Query Value** — logs read operations (4663 with ReadData)
   - ✅ **Set Value** — logs write operations (4663 with WriteData)
   - ✅ **Create Subkey** — logs subkey creation
   - ✅ **Enumerate Subkeys** — logs enumeration/listing
   - ✅ **Delete** — logs deletion attempts
6. OK → Apply → OK

---



### Configure SACL for File via PowerShell

```powershell
New-Item -Path "C:\SOCLab\audit_test.txt" -ItemType File -Force
Set-Content -Path "C:\SOCLab\audit_test.txt" -Value "Sensitive file content for audit testing"

$acl = Get-Acl "C:\SOCLab\audit_test.txt"
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "Read,Write,Delete",
    "Success,Failure"
)
$acl.AddAuditRule($auditRule)
Set-Acl "C:\SOCLab\audit_test.txt" $acl

Write-Host "File SACL configured. Ready to generate 4663 events."
```

---

## Generating the Event

### Method 1 — PowerShell Registry Access

Open PowerShell as Administrator:

```powershell
Write-Host "=== Generating 4663 events via registry access ===" -ForegroundColor Cyan

# Operation 1: Read a value — generates 4663 with ReadData/Query Value
Write-Host "Reading registry value..."
$val = Get-ItemProperty -Path "HKLM:\SOFTWARE\SOCLabAudit" -Name "ConfidentialData"
Write-Host "  Value: $($val.ConfidentialData)"

# Operation 2: Write a value — generates 4663 with WriteData/Set Value
Write-Host "Writing to registry value..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\SOCLabAudit" `
    -Name "AccessLevel" -Value "Modified_By_SOCLab"

# Operation 3: Enumerate subkeys — generates 4663 with Enumerate Subkeys
Write-Host "Enumerating subkeys..."
Get-ChildItem "HKLM:\SOFTWARE\SOCLabAudit"

# Operation 4: Get all values — generates 4663 with ReadData
Write-Host "Reading all values..."
Get-ItemProperty -Path "HKLM:\SOFTWARE\SOCLabAudit"

Write-Host ""
Write-Host "Done. Check Security log for multiple 4663 events — one per operation." -ForegroundColor Green
Write-Host "Each operation above should have generated a separate 4663 event."
```
---

<img width="468" height="330" alt="Screenshot_4" src="https://github.com/user-attachments/assets/e5c911c4-70fd-4121-a221-47a5075185bd" />

---


### Method 2 — Simulate Reconnaissance (Attacker Behaviour)

```powershell
# Simulate an attacker enumerating startup locations
Write-Host "Simulating attacker registry reconnaissance..." -ForegroundColor Yellow

$startupKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($key in $startupKeys) {
    Write-Host "Enumerating: $key"
    try {
        $entries = Get-ItemProperty -Path $key -ErrorAction Stop
        $entries.PSObject.Properties | Where-Object {
            $_.Name -notmatch "^PS"
        } | ForEach-Object {
            Write-Host "  Found: $($_.Name) = $($_.Value)"
        }
    } catch {
        Write-Host "  Access denied or key not found"
    }
}

Write-Host ""
Write-Host "Each Get-ItemProperty call above generated a 4663 event." -ForegroundColor Green
```
---

<img width="635" height="432" alt="Screenshot_3" src="https://github.com/user-attachments/assets/224a73cb-4767-443a-a42d-e7c9cee2834b" />

---


### Method 3 — File Access Trigger

```powershell
# Read access — generates 4663 with ReadData
$content = Get-Content "C:\SOCLab\audit_test.txt"
Write-Host "File read: $content"

# Write access — generates 4663 with WriteData
Add-Content -Path "C:\SOCLab\audit_test.txt" -Value "Additional line added by SOCLab"
Write-Host "Content appended to file."

Write-Host "Check Security log for 4663 events on C:\SOCLab\audit_test.txt"
```

### Method 4 — GUI Trigger

1. Open **Registry Editor**
2. Navigate to `HKLM:\SOFTWARE\SOCLabAudit`
3. Simply clicking on the key, reading values, or expanding subkeys generates 4663 events
4. Double-click any value to trigger a read operation
5. Modify a value to trigger a write operation

---

## Detecting the Event

### Method 1 — Event Viewer (GUI)

1. Open **Event Viewer** → **Windows Logs** → **Security**
2. **Filter Current Log** → Event ID: `4663` → OK
3. Look for events clustered around your trigger timestamps — you should see multiple events in rapid succession
4. Double-click each to examine the Accesses field

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Subject: Account Name | Who performed the access |
| Object Type | `Key` for registry, `File` for files |
| Object Name | Full path of the accessed object |
| Accesses | The specific operation — ReadData, WriteData, Delete, etc. |
| Access Mask | Hexadecimal representation of the access |
| Handle ID | Links back to the corresponding 4656 event |
| Process Name | Which executable performed the access |
| Process ID | Cross-reference with 4688 |

### Method 2 — PowerShell Detection

```powershell
# All 4663 events in the last hour
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4663
    StartTime = (Get-Date).AddHours(-1)
} | Select-Object TimeCreated, Message | Format-List
```

```powershell
# Detailed XML extraction of 4663 fields
$filter = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[EventID=4663]]
    </Select>
  </Query>
</QueryList>
"@

Get-WinEvent -FilterXml $filter | Select-Object -First 20 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        Account     = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        ObjectType  = ($data | Where-Object { $_.Name -eq 'ObjectType'      }).'#text'
        ObjectName  = ($data | Where-Object { $_.Name -eq 'ObjectName'      }).'#text'
        Accesses    = ($data | Where-Object { $_.Name -eq 'Accesses'        }).'#text'
        ProcessName = ($data | Where-Object { $_.Name -eq 'ProcessName'     }).'#text'
        HandleID    = ($data | Where-Object { $_.Name -eq 'HandleId'        }).'#text'
    }
} | Format-Table -AutoSize
```
---

<img width="951" height="468" alt="Screenshot_5" src="https://github.com/user-attachments/assets/d941e5f8-4110-46d8-971f-d60796099ef6" />

---


```powershell
# Hunt for suspicious write operations to Run key
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4663
    StartTime = (Get-Date).AddDays(-1)
} | Where-Object {
    $_.Message -like "*CurrentVersion\Run*" -and $_.Message -like "*WriteData*"
} | ForEach-Object {
    Write-Host "=== SUSPICIOUS WRITE TO RUN KEY ===" -ForegroundColor Red
    Write-Host "Time: $($_.TimeCreated)"
    Write-Host $_.Message
    Write-Host ""
}
```

---

## SOC Analyst Notes

### Normal vs Suspicious Access Patterns

| Pattern | Verdict |
|---|---|
| `svchost.exe` reading service registry keys at boot | Normal |
| `explorer.exe` reading file attributes as user browses | Normal |
| `powershell.exe` enumerating all Run key entries | Investigate — may be reconnaissance |
| Unknown process performing WriteData on a Run key | **High priority alert** |
| Any process performing WriteData on `HKLM\SECURITY` or `HKLM\SAM` | **Critical — credential access** |
| Burst of 4663 read events across many registry keys from one process | **Reconnaissance in progress** |

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Known process, read-only, known-good registry path |
| 🟡 Medium | Enumeration of sensitive paths by admin tools |
| 🔴 High | Write operations to startup or service keys by PowerShell |
| 🔴 Critical | Access to SAM, SECURITY hive, or LSA keys by non-system process |

### MITRE ATT&CK Reference

- **T1012** — Query Registry
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys
- **T1003.002** — OS Credential Dumping: Security Account Manager
- **T1083** — File and Directory Discovery
