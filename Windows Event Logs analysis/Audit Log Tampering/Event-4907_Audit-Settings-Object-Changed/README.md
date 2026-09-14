# Event ID 4907 — Audit Settings on Object Changed

**Log:** Security  
**Category:** Policy Change  
**Subcategory:** Other Policy Change Events  
**Level:** Information  
**Lab Environment:** Windows Server 2022 — TECHCORP / techcorp.local  
**Lab Status:** ✅ Successfully Generated

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 4907 |
| Event Name | Auditing settings on object were changed |
| Log Location | Windows Logs → Security |
| Audit Category | Policy Change |
| Audit Subcategory | Other Policy Change Events |
| Default State | Requires audit policy enabled |
| SACL Required | No — fires when SACLs are modified on other objects |

---

<img width="465" height="326" alt="Screenshot_9" src="https://github.com/user-attachments/assets/8fb2da4c-0bb1-4cfc-acd2-012cacba7375" />

---


## What Is Event 4907?

Event 4907 fires when the SACL (Security Access Control List) on a specific file, folder, or registry key is modified. A SACL is the auditing configuration attached to an individual object — it defines who is being audited, for what operations, and whether successes, failures, or both are logged.

While Event 4719 disables auditing globally across the entire system, Event 4907 represents a far more surgical approach. An attacker who removes the SACL from one specific file or folder stops auditing for that object only — everything else on the system continues logging normally. This makes the technique much harder to detect at a glance, because the audit policy settings still show everything is enabled.

### The Blind Spot Attack

The technique works like this:

```
Attacker identifies a sensitive target file or directory
→ Removes the SACL from that specific object
→ Event 4907 fires (SACL removed)
→ Attacker modifies the file — no 4663 event fires
→ Attacker reads credentials or exfiltrates data — no evidence
→ Optionally restores the SACL → Event 4907 fires again
```

Between those two 4907 events, the specific object could have been read, modified, or deleted without any corresponding access events. The SOC sees the SACL change but cannot see what happened to the object during the window when auditing was removed.

### Understanding Security Descriptors in the Event

When you look at a 4907 event, you will see two complex strings:

- **Original Security Descriptor** — what the SACL looked like before the change
- **New Security Descriptor** — what it looks like after

These strings use a format called SDDL (Security Descriptor Definition Language). They look like:
```
S:PARAI(AU;OICIСА;FA;;;WD)
```

You do not need to memorise the full SDDL syntax. The key is:
- `S:` prefix means this is the SACL section
- If the New Security Descriptor has a very short or empty SACL section — auditing was removed
- If it grew significantly — auditing was added

---

## Audit Policy Setup

```cmd
auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable
```

Verify:

```cmd
auditpol /get /subcategory:"Other Policy Change Events"
```

---

## Generating the Event

### GUI Method

1. Create a test file — open Notepad, save as `C:\SOCLab\audit_test.txt`
2. Right-click the file → **Properties** → **Security** tab → **Advanced**
3. Click the **Auditing** tab
4. Click **Add** → **Select a principal** → type `Everyone` → OK
5. Check **Full control** under Basic permissions → OK → Apply
6. Event 4907 fires — SACL was added
7. Now modify it: go back to Auditing tab → select the Everyone entry → **Edit**
8. Uncheck some permissions → OK → Apply
9. Another 4907 fires — SACL was modified
10. To simulate attacker removing auditing: select the entry → **Remove** → Apply

---

<img width="875" height="423" alt="Screenshot_1" src="https://github.com/user-attachments/assets/9c86a75b-b2ed-4c60-bd5e-e0b7107a67c1" />

---

<img width="387" height="396" alt="Screenshot_2" src="https://github.com/user-attachments/assets/90292786-bc59-4e20-af52-e32249b57cda" />

---

<img width="577" height="428" alt="Screenshot_3" src="https://github.com/user-attachments/assets/d270d3c4-2384-41e9-b21f-c2485acb07ab" />


---

<img width="688" height="454" alt="Screenshot_4" src="https://github.com/user-attachments/assets/2e0f384c-5c5f-4b9c-9abb-6abe4b2c3771" />


---

<img width="348" height="217" alt="Screenshot_5" src="https://github.com/user-attachments/assets/37bd5d15-6c79-4c06-9d1c-659dd55c1757" />

---

<img width="689" height="457" alt="Screenshot_6" src="https://github.com/user-attachments/assets/621c9a07-33a1-491e-8395-a5e86305d635" />

---

<img width="578" height="400" alt="Screenshot_7" src="https://github.com/user-attachments/assets/0002f52a-cec3-458d-afd2-07c0ef9ed6f5" />

---
### PowerShell Method


```powershell
# Create test file
New-Item -Path "C:\SOCLab\audit_test.txt" -ItemType File -Force
Set-Content "C:\SOCLab\audit_test.txt" "Sensitive data for SACL audit lab"

# Step 1: Apply initial SACL (simulates file being protected)
$acl = Get-Acl "C:\SOCLab\audit_test.txt"
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone", "FullControl", "Success"
)
$acl.AddAuditRule($auditRule)
Set-Acl "C:\SOCLab\audit_test.txt" $acl
Write-Host "SACL applied to file — Event 4907 fired (SACL added)." -ForegroundColor Green

Start-Sleep -Seconds 2

# Step 2: Remove the SACL — simulates attacker removing auditing before accessing file
$acl2 = Get-Acl "C:\SOCLab\audit_test.txt"
$acl2.RemoveAuditRuleAll(
    (New-Object System.Security.Principal.NTAccount("Everyone"))
)
Set-Acl "C:\SOCLab\audit_test.txt" $acl2
Write-Host "SACL removed — Event 4907 fired (SACL removed)." -ForegroundColor Red
Write-Host "File can now be accessed without generating audit events." -ForegroundColor Yellow
```





## Detecting the Event

### GUI — Event Viewer

1. Event Viewer → Windows Logs → **Security**
2. Filter → Event ID: `4907` → OK
3. Look for events near the time of your SACL changes
4. Open each event and compare Original vs New Security Descriptor

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Object Name | Which file or folder had its SACL modified |
| Original Security Descriptor | What the auditing was before |
| New Security Descriptor | What it is now — shorter = auditing reduced or removed |
| Subject: Account Name | Who made the SACL change |
| Process Name | `explorer.exe` = GUI method / `powershell.exe` = script method |

---

<img width="624" height="267" alt="Screenshot_8" src="https://github.com/user-attachments/assets/f76a1ff9-1d10-42d0-9219-598762b35228" />

---

<img width="465" height="326" alt="Screenshot_9" src="https://github.com/user-attachments/assets/694cdac9-f074-4f15-b404-b241659e1713" />

---

<img width="469" height="328" alt="Screenshot_10" src="https://github.com/user-attachments/assets/53bc259d-4511-4828-a8d2-244a00f5087c" />

---

<img width="467" height="329" alt="Screenshot_11" src="https://github.com/user-attachments/assets/dabdc572-d33a-4cf6-9ecc-e17924b2fbf0" />

---


### PowerShell Detection

```powershell
# Find all SACL modification events
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4907
    StartTime = (Get-Date).AddDays(-7)
} | Select-Object TimeCreated, Message | Format-List
```
---

<img width="949" height="434" alt="asd" src="https://github.com/user-attachments/assets/b2fc963e-9f4e-4167-ba37-b46fa3d5cb17" />

---


```powershell
# Extract object names from 4907 events
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4907
    StartTime = (Get-Date).AddDays(-7)
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        ObjectName  = ($data | Where-Object { $_.Name -eq 'ObjectName'   }).'#text'
        AccountName = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        ProcessName = ($data | Where-Object { $_.Name -eq 'ProcessName'  }).'#text'
    }
} | Format-Table -AutoSize
```


---


## SOC Analyst Notes

### What to Do When You Find 4907

When you find a 4907 showing a SACL was removed from a sensitive object, your immediate question is: what happened to that object between the removal and the restoration? Look for the absence of expected events — if a file was being actively written to before the SACL was removed, and suddenly there are no file access events for it, that gap is the evidence.

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Known admin modifying SACL on non-sensitive file during setup |
| 🟡 Medium | SACL removed from any file in sensitive directory |
| 🔴 High | SACL removed then restored — blind spot attack pattern |
| 🔴 Critical | SACL removed from system files, credential stores, or log directories |

### MITRE ATT&CK Reference

- **T1562.002** — Impair Defenses: Disable Windows Event Logging
- **T1070** — Indicator Removal on Host
