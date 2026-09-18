# Sysmon Event ID 22 — DNS Query

**Log Name:** Microsoft-Windows-Sysmon/Operational  
**Source:** Sysmon  
**Level:** Information  
**Task Category:** Dns query (rule:DnsQuery)  
**Lab Status:** ✅ Successfully Generated

---

## Introduction

Event ID 22 is generated whenever a process on the system makes a DNS query. This is one of the most valuable Sysmon events for SOC analysts because it shows **which process** is performing the DNS lookup, what domain or IP it is querying, and under which user context.

Unlike native Windows DNS logs, Sysmon Event 22 directly links the DNS request to the process that initiated it. This makes it extremely useful for detecting:

- Command and Control (C2) communication
- Malware beaconing
- Living-off-the-land techniques
- Suspicious processes making unexpected DNS requests

In real SOC environments, analysts frequently hunt for processes like `powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe`, or unknown executables making DNS queries to unusual domains.

---


<img width="345" height="446" alt="Screenshot_8" src="https://github.com/user-attachments/assets/5a7a637f-67a0-4e55-a8ca-05cabc8f0dc1" />

---

<img width="218" height="281" alt="Screenshot_9" src="https://github.com/user-attachments/assets/2fdba7f9-a5ec-4d4f-adb1-02f4f4829524" />

---



<img width="616" height="301" alt="Screenshot_1" src="https://github.com/user-attachments/assets/bfd7d57a-ffd5-48af-8184-f6c52d74bed0" />

---


## How to Generate Event 22

**PowerShell Method:**
```powershell
Resolve-DnsName google.com
```

**CMD Method:**
```cmd
nslookup google.com
```

**Alternative:**
```powershell
Test-NetConnection google.com -Port 443
```

---

<img width="541" height="234" alt="Screenshot_11" src="https://github.com/user-attachments/assets/f2fec018-191d-42c6-890b-24f5460f4bf3" />

---

<img width="363" height="112" alt="Screenshot_12" src="https://github.com/user-attachments/assets/40188cfc-bfcb-4f53-8383-f36b375fe886" />

---


## Detection Commands

### Basic Detection

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 |
Where-Object { $_.Id -eq 22 } |
Select-Object TimeCreated, Message |
Format-List
```
---

<img width="642" height="455" alt="Screenshot_10" src="https://github.com/user-attachments/assets/27bd1e45-88ef-4db2-a29e-99226c46e8d9" />

---


### Clean Table Format (Recommended)

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 30 |
Where-Object { $_.Id -eq 22 } |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time     = $_.TimeCreated
        Process  = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'}).'#text'
        Query    = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'QueryName'}).'#text'
        User     = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'}).'#text'
        Status   = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'QueryStatus'}).'#text'
    }
} | Format-Table -AutoSize
```


---

<img width="803" height="348" alt="Screenshot_13" src="https://github.com/user-attachments/assets/265dfe84-acdc-40a7-9f0d-013a48b4bd9e" />

---

### Hunt for Suspicious Processes

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50 |
Where-Object { 
    $_.Id -eq 22 -and 
    (
        $_.Message -like "*powershell*" -or
        $_.Message -like "*cmd.exe*" -or
        $_.Message -like "*wscript*" -or
        $_.Message -like "*mshta*" -or
        $_.Message -like "*rundll32*"
    )
} | Format-List TimeCreated, Message
```

---

## Key Fields to Analyze

| Field         | Description                              | What to Look For                          |
|---------------|------------------------------------------|-------------------------------------------|
| Image         | Full path of the process                 | Unusual or temporary paths                |
| QueryName     | Domain or hostname being queried         | Strange, long, or random domains          |
| QueryResults  | IP address returned                      | External IPs vs internal                  |
| User          | Account that ran the process             | SYSTEM vs normal user                     |
| QueryStatus   | 0 = Success                              | Failed queries can also be interesting    |

---

## SOC Analyst Notes

**High Priority:**
- `powershell.exe` or `cmd.exe` making DNS queries to external domains
- Processes from Temp, AppData, or Downloads folders
- High frequency of DNS queries from the same process (beaconing)

**Normal/Expected:**
- `lsass.exe`
- `svchost.exe`
- Browsers (`chrome.exe`, `msedge.exe`)
- Active Directory related processes on Domain Controllers

---

## MITRE ATT&CK Mapping

- **T1071.004** — Application Layer Protocol: DNS
- **T1568** — Dynamic Resolution
