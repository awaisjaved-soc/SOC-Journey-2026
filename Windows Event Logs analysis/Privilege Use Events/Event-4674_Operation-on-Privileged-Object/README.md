# Event ID 4674 — Operation on Privileged Object

**Log:** Security  
**Category:** Privilege Use  
**Subcategory:** Sensitive Privilege Use  
**Level:** Information  
**Lab Environment:** Windows Server 2022 — TECHCORP / techcorp.local  
**Lab Status:** ✅ Successfully Generated

---

## Event Overview

| Field              | Detail                                      |
|--------------------|---------------------------------------------|
| Event ID           | 4674                                        |
| Event Name         | An operation was attempted on a privileged object |
| Log Location       | Windows Logs → Security                     |
| Audit Subcategory  | Sensitive Privilege Use                     |
| Default State      | Disabled — must be manually enabled         |
| Volume             | Medium                                      |

---

## What Is Event 4674?

Event 4674 is generated when an operation is attempted on a **privileged object**. 

A privileged object is an object that has a System Access Control List (SACL) or requires special privileges to access.

This event is more specific than 4673 because it ties the privilege use to a particular object (file, registry key, etc.).

### When you will see this event in SOC work:

- Attacker trying to modify security descriptors on sensitive registry keys
- Process trying to access protected files with elevated privileges
- Attempts to modify audit policies on specific objects
- Robocopy or backup tools using special privileges

---

## Audit Policy Setup

Same as Event 4673:

```powershell
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
gpupdate /force
```

Verify:

```powershell
auditpol /get /subcategory:"Sensitive Privilege Use"
```

---

## How to Generate Event 4674

### Method 1 — Robocopy (Most Reliable for Lab)

```powershell
New-Item -Path "C:\Temp" -ItemType Directory -Force
robocopy C:\Windows\System32 C:\Temp kernel32.dll /B
```

This command generated Event 4674 with `SeTakeOwnershipPrivilege` in the lab.

### Method 2 — Access Protected Registry Key

```powershell
reg query HKLM\SAM\SAM
```

### Method 3 — Access Security Related Objects

```powershell
Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue
```

---

## Detection Commands

### Basic Detection

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4674} -MaxEvents 10 |
Select-Object TimeCreated, Message | Format-List
```

### Better Formatted Detection

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4674} -MaxEvents 15 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time      = $_.TimeCreated
        User      = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
        Privilege = ($xml.Event.EventData.Data | Where {$_.Name -eq 'PrivilegeList'}).'#text'
        Process   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'ProcessName'}).'#text'
        Object    = ($xml.Event.EventData.Data | Where {$_.Name -eq 'ObjectName'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## Privilege Explanation (From Lab)

In the lab we saw these privileges:

| Privilege                        | Meaning                                      | Risk     |
|----------------------------------|----------------------------------------------|----------|
| SeTakeOwnershipPrivilege         | Take ownership of any object                 | High     |
| SeTcbPrivilege                   | Act as part of the OS                        | Critical |
| SeSecurityPrivilege              | Manage auditing and security log             | High     |
| SeProfileSingleProcessPrivilege  | Profile other processes                       | Medium   |

---

## How Attackers Abuse These Privileges

1. Attacker runs `whoami /priv` to list available privileges
2. Finds powerful privileges (especially SeDebugPrivilege or SeTakeOwnershipPrivilege)
3. Uses tools to abuse them (Mimikatz, custom scripts, etc.)
4. Escalates privileges or dumps credentials
5. May also clear logs using SeSecurityPrivilege

---

## SOC Analyst Notes

**High Priority Alerts:**
- SeTakeOwnershipPrivilege used by unexpected processes
- SeDebugPrivilege used by non-security tools
- Privilege use from normal user accounts

**Common Noise:**
- lsass.exe
- WmiPrvSE.exe
- Legitimate backup software

---

## MITRE ATT&CK Mapping

- **T1134** — Access Token Manipulation
- **T1222** — File and Directory Permissions Modification
- **T1003** — OS Credential Dumping
