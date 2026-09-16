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

<img width="467" height="330" alt="Screenshot_1" src="https://github.com/user-attachments/assets/e9269320-e441-40a5-8f9a-e64a2faa2d7a" />

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


<img width="741" height="399" alt="Screenshot_11" src="https://github.com/user-attachments/assets/71e2c26b-6ab1-47e6-acfa-8e31a9062cfd" />

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

<img width="721" height="235" alt="asdasd" src="https://github.com/user-attachments/assets/f07ab105-f55f-45a7-b08f-b9275bad295a" />

---



## How to Generate Event 4673

### Method 1 — Robocopy Backup Mode (Most Reliable)

```powershell
# Create Temp folder
New-Item -Path "C:\Temp" -ItemType Directory -Force

# Force SeBackupPrivilege / related privileges
robocopy C:\Windows\System32 C:\Temp kernel32.dll /B
```
---

<img width="528" height="473" alt="Screenshot_13" src="https://github.com/user-attachments/assets/f6856075-7b87-45bf-b46d-e55cb8aa71ba" />

---

The `/B` switch runs Robocopy in Backup mode and forces privilege use.

### Method 2 — Access LSASS Information

```powershell
Get-Process lsass
```

---


<img width="412" height="78" alt="Screenshot_12" src="https://github.com/user-attachments/assets/28e71056-3c0a-4734-b9c4-bb52a43cb057" />

---

### Method 3 — Check current privileges

```powershell
whoami /priv
```


---

<img width="741" height="399" alt="Screenshot_11" src="https://github.com/user-attachments/assets/5beb700b-8058-4440-94e8-81a680df88bb" />

---


## Detection Commands

### Basic Detection

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4673} -MaxEvents 10 |
Select-Object TimeCreated, Message | Format-List
```
---

<img width="628" height="253" alt="Screenshot_3" src="https://github.com/user-attachments/assets/ca0d9554-c313-4691-9106-02094ea20beb" />

---

<img width="466" height="331" alt="Screenshot_4" src="https://github.com/user-attachments/assets/11abc353-5f0b-4093-87b2-6100688177d6" />

---

<img width="471" height="329" alt="Screenshot_5" src="https://github.com/user-attachments/assets/90d5ec68-2c8e-48a8-acce-7de12bf24412" />

---
<img width="469" height="331" alt="Screenshot_6" src="https://github.com/user-attachments/assets/3c9f3f81-19bb-4cd8-b12e-90caa0f0cc17" />

---

<img width="469" height="331" alt="Screenshot_7" src="https://github.com/user-attachments/assets/dbe8d8c3-7794-494f-a930-1c80b06e6a92" />

---
<img width="468" height="330" alt="Screenshot_8" src="https://github.com/user-attachments/assets/b3585339-b741-452f-91f5-dd0026e4df09" />

---


<img width="467" height="330" alt="Screenshot_1" src="https://github.com/user-attachments/assets/93461ba9-fe62-4316-8350-eca58b984651" />

---


<img width="469" height="329" alt="Screenshot_2" src="https://github.com/user-attachments/assets/c7b755b2-dfd2-4049-ae81-897066263fc5" />

---

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

<img width="665" height="303" alt="Screenshot_10" src="https://github.com/user-attachments/assets/4f447226-5837-4030-9050-5a2ff14e76ec" />

---

<img width="673" height="110" alt="Screenshot_9" src="https://github.com/user-attachments/assets/d681a84f-9287-4d98-93ff-d7a38a3ec69a" />

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
