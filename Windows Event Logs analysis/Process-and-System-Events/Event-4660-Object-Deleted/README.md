# Event ID 4660 — An Object Was Deleted

**Log:** Security  
**Category:** Object Access  
**Subcategory:** Handle Manipulation  
**Level:** Information  
**Lab Environment:** Windows Server 2019 — TECHCORP / techcorp.local

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 4660 |
| Event Name | An object was deleted |
| Log Location | Windows Logs → Security |
| Audit Category | Object Access |
| Audit Subcategory | Handle Manipulation |
| Default State | Disabled — requires audit policy AND SACL with Delete permission |
| Object Types | Registry Key, File, Directory |

---

## What Is Event 4660?

Event 4660 fires at the moment a registry key, file, or directory that has been configured for auditing is permanently deleted. It is one of the simplest events in terms of what it records, but also one of the most forensically important — because deletion is the primary method attackers use to destroy evidence of their presence.

However, Event 4660 has a critical limitation that every SOC analyst must understand: **it does not contain the name of the deleted object**. The event only contains a Handle ID, a process ID, and the account that performed the deletion. The object name was recorded in an earlier Event 4656 when the handle to the object was first requested. To reconstruct what was deleted, you must correlate Event 4660 with the matching Event 4656 using the Handle ID.

This correlation requirement is not a design flaw — it reflects the reality of how deletion works at the OS level. By the time the deletion is confirmed, the object no longer exists. Windows uses the Handle ID as the link back to the pre-deletion record.

---

## The Anti-Forensics Connection

Event 4660 is particularly relevant to **anti-forensics** — a category of attacker techniques designed to hinder investigation and incident response. Common anti-forensic deletion targets include:

**Malware cleanup** — After establishing persistence through other means (scheduled tasks, services, registry), attackers delete the dropper or installer executable they originally used. The persistence mechanism survives but the initial payload disappears.

**Log tampering** — Attackers with sufficient privileges may attempt to delete individual log files from `C:\Windows\System32\winevt\Logs\` to erase their activity records. Event 4660 on a log file is a critical indicator.

**Tool removal** — Hacking tools, credential dumpers, lateral movement utilities, and network scanners are deleted from disk after use.

**Evidence file removal** — Configuration files, staging directories, and temporary files used during the attack are cleaned up.

**Registry cleanup** — Registry keys created during the attack (for persistence, configuration storage, or tool staging) are deleted once they are no longer needed.

A defender who sees 4660 events appearing in rapid succession from an unfamiliar process should treat it as a high-priority incident — something is being cleaned up.

---

## What You Will See on Screen

If you have Registry Editor open and are viewing the key being deleted, you will see it disappear from the tree view. For file deletions, the file will disappear from Explorer. Other than that, nothing happens visually. The 4660 event fires in the kernel and is written to the Security log silently. Your evidence is in Event Viewer, correlated with the matching 4656.

---

## Audit Policy Setup

### Method 1 — Group Policy (GUI)

1. Open **Group Policy Management** → right-click domain → **Edit**
2. Navigate to: `Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Object Access`
3. Enable both **Audit Handle Manipulation** and **Audit File System** and **Audit Registry**
4. Set each to **Success and Failure**
5. Run `gpupdate /force`

### Method 2 — Command Line (Recommended for Lab)

```cmd
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
```

Verify:

```cmd
auditpol /get /subcategory:"Handle Manipulation"
auditpol /get /subcategory:"Registry"
auditpol /get /subcategory:"File System"
```

---

## SACL Configuration

### For Registry Key Deletion

1. Open **Registry Editor** as Administrator
2. Navigate to the key you want to audit deletions on, or create a test key:

```powershell
# Create a test key to audit
New-Item -Path "HKLM:\SOFTWARE\SOCLabDeleteTest" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\SOCLabDeleteTest" `
    -Name "TestValue" -Value "SensitiveData" -PropertyType String
```

3. In Registry Editor, right-click `SOCLabDeleteTest` → **Permissions** → **Advanced** → **Auditing**
4. Click **Add** → `Everyone` → OK
5. Type: `Success` | Applies to: `This key and subkeys`
6. Check: ✅ **Delete** and ✅ **Read Control**
7. OK → Apply → OK

### For File Deletion (PowerShell SACL)

```powershell
# Create a test file to audit
New-Item -Path "C:\SOCLab" -ItemType Directory -Force
New-Item -Path "C:\SOCLab\sensitive_report.txt" -ItemType File -Force
Set-Content -Path "C:\SOCLab\sensitive_report.txt" -Value "Confidential Financial Data"

# Apply auditing SACL to the file
$acl = Get-Acl "C:\SOCLab\sensitive_report.txt"
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "Delete,DeleteSubdirectoriesAndFiles",
    "Success"
)
$acl.AddAuditRule($auditRule)
Set-Acl "C:\SOCLab\sensitive_report.txt" $acl

Write-Host "SACL applied. File is now being audited for deletion."
```

---

## Generating the Event

### Method 1 — PowerShell Registry Deletion

Open PowerShell as Administrator:

```powershell
# Ensure test key exists
New-Item -Path "HKLM:\SOFTWARE\SOCLabDeleteTest" -Force -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\SOCLabDeleteTest" `
    -Name "EvidenceFile" -Value "SensitiveData" -PropertyType String -Force

Write-Host "Test key created at HKLM:\SOFTWARE\SOCLabDeleteTest"
Write-Host "Deleting now to generate Event 4660..."

# This deletion fires Event 4660
# Windows checks the SACL on the key, sees Delete is audited, writes 4660
Remove-Item -Path "HKLM:\SOFTWARE\SOCLabDeleteTest" -Force -Recurse

Write-Host "Key deleted. Check Security log for Event ID 4660."
Write-Host "Note: The event will not contain the key name. Correlate with 4656 using Handle ID."
```

### Method 2 — PowerShell File Deletion

```powershell
# Ensure test file and SACL exist
New-Item -Path "C:\SOCLab" -ItemType Directory -Force -ErrorAction SilentlyContinue
Set-Content -Path "C:\SOCLab\sensitive_report.txt" -Value "Confidential Data" -Force

# Apply SACL
$acl = Get-Acl "C:\SOCLab\sensitive_report.txt"
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone", "Delete", "Success"
)
$acl.AddAuditRule($auditRule)
Set-Acl "C:\SOCLab\sensitive_report.txt" $acl

Write-Host "Deleting audited file..."

# Delete — fires 4660
Remove-Item "C:\SOCLab\sensitive_report.txt" -Force

Write-Host "File deleted. Check Security log for Event ID 4660."
```

### Method 3 — GUI Trigger

1. Create a test registry key or file manually
2. Configure its SACL as described above
3. In Registry Editor, right-click the key → **Delete** → confirm
4. For files: select the file in Explorer → press Delete → confirm

---

## Detecting the Event

### Method 1 — Event Viewer (GUI)

1. Open **Event Viewer** → **Windows Logs** → **Security**
2. Click **Filter Current Log** → Event ID: `4660` → OK
3. Locate events matching your trigger timestamp
4. Double-click to view details
5. **Note the Handle ID** — search for a 4656 event with the same Handle ID to find the object name

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Subject: Account Name | Who deleted the object |
| Subject: Logon ID | Links to logon session |
| Handle ID | **Critical** — use this to find the matching 4656 event |
| Process ID | Which process performed the deletion |
| Transaction ID | Groups related operations |

> There is no Object Name field in 4660. You must look up the Handle ID in the corresponding 4656 event.

### Method 2 — PowerShell Detection

```powershell
# Find all deletion events in the last hour
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4660
    StartTime = (Get-Date).AddHours(-1)
} | Select-Object TimeCreated, Message | Format-List
```

```powershell
# Extract Handle IDs from 4660 events, then correlate with 4656
$deletions = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4660
    StartTime = (Get-Date).AddHours(-1)
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        AccountName = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        HandleID    = ($data | Where-Object { $_.Name -eq 'HandleId'        }).'#text'
        ProcessID   = ($data | Where-Object { $_.Name -eq 'ProcessId'       }).'#text'
    }
}

Write-Host "=== Deletion Events Found ===" -ForegroundColor Yellow
$deletions | Format-Table -AutoSize

Write-Host ""
Write-Host "Now searching for matching 4656 events by Handle ID..." -ForegroundColor Cyan

foreach ($del in $deletions) {
    $matchingHandle = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4656
        StartTime = $del.Time.AddMinutes(-5)
        EndTime   = $del.Time
    } | Where-Object {
        $_.Message -like "*$($del.HandleID)*"
    } | Select-Object -First 1

    if ($matchingHandle) {
        Write-Host "Match found for Handle $($del.HandleID):" -ForegroundColor Green
        Write-Host $matchingHandle.Message
    }
}
```

---

## SOC Analyst Notes

### The Handle ID Correlation Workflow

When you find a 4660 event, your investigation workflow should be:

```
Step 1: Open 4660 event → note the Handle ID and timestamp
Step 2: Search Security log for 4656 events in the 5 minutes BEFORE the 4660
Step 3: Find the 4656 with the matching Handle ID
Step 4: Read the Object Name from 4656 — this is what was deleted
Step 5: Note the Process Name and Account Name
Step 6: Search for 4688 process creation to understand what spawned that process
```

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Normal file deletion by user in their own directory |
| 🟡 Medium | Deletion of system files by an administrator account |
| 🔴 High | Unknown process deleting files from System32, Logs directory, or registry keys |
| 🔴 Critical | Multiple rapid 4660 events from same process — mass deletion / evidence destruction in progress |

### MITRE ATT&CK Reference

- **T1070.004** — Indicator Removal: File Deletion
- **T1070.001** — Indicator Removal: Clear Windows Event Logs
- **T1112** — Modify Registry (registry key deletion)
- **T1485** — Data Destruction
