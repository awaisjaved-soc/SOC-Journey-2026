# Event 4697 – A Service Was Installed in the System.

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4697 |
| **Category** | Process & System Events |
| **Log** | Security |
| **Tier** | 🟠 Tier 2 – High Value |
| **SOC Importance** | 🔴 High |

## What Is This Event?

Event 4697 is the **Security log version** of Event 7045. Both events fire when a new service is installed — 7045 goes to the System log and 4697 goes to the Security log. Always monitor and document both because:

- Attackers who clear one log may not clear the other
- Event 4697 includes the **account that installed the service**, making it more useful for attribution
- Having both gives you redundancy in detection

This event requires an audit policy to be manually enabled — it does not log by default unlike 7045.

---

## Audit Policy – Must Enable First

```powershell
# Enable Security System Extension auditing
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
gpupdate /force
```

### Verify
```powershell
auditpol /get /subcategory:"Security System Extension"
```

Expected output: `Security System Extension   Success and Failure`

---

## How to Generate This Event

### Method 1 – PowerShell
```powershell
# Generates BOTH 7045 (System log) and 4697 (Security log)
New-Service -Name "TestService4697" `
  -BinaryPathName "C:\Windows\System32\notepad.exe" `
  -DisplayName "SOC Lab Service 4697" `
  -StartupType Manual
```
---
<img width="628" height="417" alt="Screenshot_2" src="https://github.com/user-attachments/assets/e386650f-e64b-4371-8421-28ad593df0c8" />

---

<img width="610" height="421" alt="Screenshot_6" src="https://github.com/user-attachments/assets/8ec03095-47f2-41ff-861d-6007e0acf594" />

---


### Method 2 – sc.exe
```powershell
sc.exe create "LabService4697" binPath= "C:\Windows\System32\cmd.exe" start= demand
```

---

## How to Detect This Event

### GUI Method
1. Open **Event Viewer** (`eventvwr.msc`)
2. Go to **Windows Logs → Security**
3. Click **Filter Current Log**
4. Enter Event ID: `4697`
5. Click OK

### PowerShell Method
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        ServiceName = ($xml.Event.EventData.Data | Where {$_.Name -eq 'ServiceName'}).'#text'
        ImagePath   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'ServiceFileName'}).'#text'
        StartType   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'ServiceStartType'}).'#text'
        InstalledBy = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
    }
} | Format-Table -AutoSize -Wrap
```

---

<img width="674" height="382" alt="Screenshot_3" src="https://github.com/user-attachments/assets/ceced2ec-125a-4735-8e6c-defddab342fa" />

---

<img width="615" height="424" alt="Screenshot_1" src="https://github.com/user-attachments/assets/96039a79-18bb-495c-9163-edd610b0d72a" />

---



### Detect Both 7045 and 4697 Together
```powershell
# System log – 7045
Write-Host "=== Event 7045 (System Log) ===" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 3 |
Select-Object TimeCreated, Message | Format-List

# Security log – 4697
Write-Host "=== Event 4697 (Security Log) ===" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697} -MaxEvents 3 |
Select-Object TimeCreated, Message | Format-List
```

---


<img width="678" height="385" alt="Screenshot_4" src="https://github.com/user-attachments/assets/b02bd8f8-420c-40a3-8b22-d1246eac1ff0" />

---

<img width="674" height="385" alt="Screenshot_5" src="https://github.com/user-attachments/assets/59ea8dd3-ef0f-430e-8ca6-f7788e6b8257" />

---


## Cleanup After Lab

```powershell
sc.exe delete "TestService4697"
sc.exe delete "LabService4697"
```

---

<img width="674" height="384" alt="Screenshot_7" src="https://github.com/user-attachments/assets/e132d486-4b68-46cd-9dd1-2c5f5435b252" />

---


## 7045 vs 4697 – Key Differences

| Feature | 7045 | 4697 |
|---------|------|------|
| Log Location | System | Security |
| Shows installer account | ❌ No | ✅ Yes |
| Enabled by default | ✅ Yes | ❌ Needs audit policy |
| Best for | Quick detection | Attribution and investigation |
| Attacker may clear | System log | Security log |

> **Always check both logs.** An attacker may clear the Security log but forget the System log, or vice versa. Having both monitored gives you redundancy.

---

## SOC Analyst Notes

| Scenario | Risk |
|----------|------|
| Service installed by `SYSTEM` or unknown account | 🔴 Investigate |
| 4697 exists but no matching 7045 | 🟡 Log may have been partially cleared |
| Service binary path is suspicious | 🔴 Malware |
| Installation during off-hours | 🟡 Suspicious |

### Related Events

| Event ID | Log | Relationship |
|----------|-----|-------------|
| 7045 | System | Same event — System log version |
| 7036 | System | Service started after installation |
| 7040 | System | Start type changed |
| 4688 | Security | Process launched by the service |
