# Event ID 4673 — Sensitive Privilege Use Attempted

**Log:** Security  
**Category:** Privilege Use  
**Subcategory:** Sensitive Privilege Use  
**Level:** Information / Failure  
**Lab Environment:** Windows Server 2022 — TECHCORP / techcorp.local  
**Lab Status:** ✅ Successfully Generated

---

## Event Overview

| Field              | Detail                                      |
|--------------------|---------------------------------------------|
| Event ID           | 4673                                        |
| Event Name         | Sensitive Privilege Use Attempted           |
| Log Location       | Windows Logs → Security                     |
| Audit Subcategory  | Sensitive Privilege Use                     |
| Default State      | Disabled — must be manually enabled         |
| Volume             | Medium to High on Domain Controllers        |

---

## What Is Event 4673?

Event 4673 is generated when a process tries to **use** a sensitive privilege that is already present in its access token.

This event does **not** mean the privilege was granted. It means the privilege was **invoked** (used).

Common privileges that trigger this event:

| Privilege                        | Why Attackers Want It                              |
|----------------------------------|----------------------------------------------------|
| SeDebugPrivilege                 | Debug/inject into other processes (LSASS dumping)  |
| SeTcbPrivilege                   | Act as part of the operating system                |
| SeLoadDriverPrivilege            | Load malicious kernel drivers                      |
| SeBackupPrivilege                | Read any file ignoring ACLs                        |
| SeRestorePrivilege               | Write any file ignoring ACLs                       |
| SeSecurityPrivilege              | Manage audit logs                                  |
| SeTakeOwnershipPrivilege         | Take ownership of any object                       |
| SeProfileSingleProcessPrivilege  | Profile other processes                             |

---

## Audit Policy Setup

```powershell
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
gpupdate /force
```

Verify:

```powershell
auditpol /get /subcategory:"Sensitive Privilege Use"
```

---

## How to Generate Event 4673

### Method 1 — Robocopy Backup Mode (Most Reliable)

```powershell
# Create Temp folder
New-Item -Path "C:\Temp" -ItemType Directory -Force

# Force SeBackupPrivilege / related privileges
robocopy C:\Windows\System32 C:\Temp kernel32.dll /B
```

The `/B` switch runs Robocopy in Backup mode and forces privilege use.

### Method 2 — Access LSASS Information

```powershell
Get-Process lsass
```

### Method 3 — Check current privileges

```powershell
whoami /priv
```

---

## Detection Commands

### Basic Detection

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4673} -MaxEvents 10 |
Select-Object TimeCreated, Message | Format-List
```

### Better Formatted Detection

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4673} -MaxEvents 15 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time      = $_.TimeCreated
        User      = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
        Privilege = ($xml.Event.EventData.Data | Where {$_.Name -eq 'PrivilegeList'}).'#text'
        Process   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'ProcessName'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## How Attackers Enumerate Privileges

After gaining access, attackers check their current privileges:

```powershell
whoami /priv
whoami /all
```

They also use tools like Seatbelt, SharpUp, PowerUp, and WinPEAS.

Once powerful privileges are found, they are abused for:

- Credential dumping (SeDebugPrivilege)
- Taking ownership of files (SeTakeOwnershipPrivilege)
- Loading drivers (SeLoadDriverPrivilege)
- Clearing logs (SeSecurityPrivilege)

---

## SOC Analyst Notes

**What to look for:**
- Non-admin accounts using SeDebugPrivilege
- High frequency of 4673 from a single account
- SeLoadDriverPrivilege from unexpected processes
- Privilege use outside normal working hours

**Common False Positives:**
- Antivirus / EDR tools using SeDebugPrivilege
- Backup software using SeBackupPrivilege
- System processes (lsass.exe, WmiPrvSE.exe)

---

## MITRE ATT&CK Mapping

- **T1134** — Access Token Manipulation
- **T1003** — OS Credential Dumping (when SeDebugPrivilege is used)
- **T1543** — Create or Modify System Process
