# Event ID 4946 — Firewall Rule Added

**Log:** Security  
**Category:** Policy Change  
**Subcategory:** MPSSVC Rule-Level Policy Change  
**Level:** Information  
**Lab Environment:** Windows Server 2022 — TECHCORP / techcorp.local  
**Lab Status:** ✅ Successfully Generated

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 4946 |
| Event Name | A change has been made to Windows Firewall exception list — a rule was added |
| Log Location | Windows Logs → Security |
| Audit Subcategory | MPSSVC Rule-Level Policy Change |
| Default State | Disabled — must be manually enabled |
| SACL Required | No |
| Volume | Low — only fires when a firewall rule is created |

---

## What Is Event 4946?

Event 4946 fires every time a new rule is added to Windows Firewall. This is one of the most actionable events in the entire Network and Firewall category because legitimate firewall rule changes are rare, controlled events that should always be documented and approved. In a well-managed environment, new firewall rules are created by IT administrators following a change management process — not by random processes at unexpected times.

When an unexpected 4946 appears — especially one that adds an inbound Allow rule, or allows a specific process to communicate externally — that is an immediate red flag. Attackers add firewall rules to ensure their tools can communicate without being blocked. A backdoor process that needs to accept incoming connections will add an inbound Allow rule so Windows Firewall does not stop the incoming traffic. A C2 beacon that needs to reach an external server will add an outbound Allow rule to bypass any existing restrictions.

### What Makes a 4946 Event Suspicious

Not all new firewall rules are equal. Severity depends heavily on:

**Direction** — Inbound Allow rules are more suspicious than Outbound rules because they expose the machine to incoming connections.

**Scope** — A rule allowing all traffic on all ports from any source is far more suspicious than a narrowly scoped rule for a specific application and port.

**Timing** — A rule created at 3 AM from a PowerShell process is far more suspicious than one created during business hours from the firewall management console.

**Process** — Rules created by `powershell.exe`, `cmd.exe`, or unknown processes are more suspicious than those created by the Windows Firewall service itself during software installation.

---

## Audit Policy Setup

```cmd
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
```
---

<img width="953" height="486" alt="Screenshot_6" src="https://github.com/user-attachments/assets/ba66f542-4287-4a01-b841-14d3d685c5ac" />

---

<img width="370" height="421" alt="Screenshot_8" src="https://github.com/user-attachments/assets/ecda4aaf-7d70-4a11-81ba-6c25c339f7c8" />

---



Verify:

```cmd
auditpol /get /subcategory:"MPSSVC Rule-Level Policy Change"
```

---

<img width="903" height="429" alt="Screenshot_5" src="https://github.com/user-attachments/assets/bcb1870a-e7c7-476a-9365-c44d422fc339" />

---


> This subcategory covers 4946, 4947, 4948, and 4954 — enable it once for all four events.

---

## Generating the Event

### GUI Method

1. Open **Windows Defender Firewall with Advanced Security** (`wf.msc`)
2. Click **Inbound Rules** in the left panel
3. Click **New Rule** in the right panel
4. Select **Port** → TCP → Specific local ports: `4444`
5. Select **Allow the connection**
6. Apply to all profiles (Domain, Private, Public)
7. Name it `SOC-Lab-Test-Rule` → Finish
8. Event 4946 fires immediately
9. Delete the rule after screenshot: right-click → **Delete**

---

<img width="563" height="427" alt="Screenshot_1" src="https://github.com/user-attachments/assets/7b46e1a7-f66f-4145-920c-f7862db18c27" />

---

<img width="483" height="343" alt="Screenshot_10" src="https://github.com/user-attachments/assets/08eb0742-273d-4ca4-a241-8fe8b9a4e3bb" />

---

<img width="459" height="159" alt="Screenshot_2" src="https://github.com/user-attachments/assets/70b2e2e7-2406-4f4d-b8bd-5d077fe4374a" />

---

### PowerShell Method

```powershell
# Add a new inbound allow rule — simulates attacker opening a port
New-NetFirewallRule `
    -DisplayName "SOC-Lab-Inbound-Test" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 4444 `
    -Action Allow
Write-Host "Firewall rule added — Event 4946 generated." -ForegroundColor Yellow
Write-Host "Take screenshot now." -ForegroundColor Cyan

# Remove after screenshot
Remove-NetFirewallRule -DisplayName "SOC-Lab-Inbound-Test"
Write-Host "Rule removed." -ForegroundColor Green
```

---

<img width="906" height="441" alt="Screenshot_3" src="https://github.com/user-attachments/assets/6dd7e005-9502-4e47-b5e7-c230784d7681" />

---


<img width="717" height="184" alt="Screenshot_4" src="https://github.com/user-attachments/assets/abda9387-5b3a-4cea-aed1-463170d8cc91" />

---

<img width="903" height="429" alt="Screenshot_5" src="https://github.com/user-attachments/assets/08460011-6163-4609-b58e-332a5ec119c7" />

---



## Detecting the Event

### GUI — Event Viewer

1. Event Viewer → Windows Logs → **Security**
2. Filter → Event ID: `4946` → OK
3. Each entry shows a new firewall rule that was created

---

<img width="355" height="171" alt="Screenshot_9" src="https://github.com/user-attachments/assets/41419c18-c23f-4091-b4eb-721d3bc2fdc0" />


---

<img width="458" height="78" alt="Screenshot_11" src="https://github.com/user-attachments/assets/51e01141-70ef-4a43-ba3d-c949ae1d162a" />

---

<img width="470" height="329" alt="Screenshot_12" src="https://github.com/user-attachments/assets/b63aa8d7-3b33-4162-869a-249b1b297b86" />

---

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Rule Name | Name of the new rule — attacker rules often have generic or system-like names |
| Profile Used | Domain/Private/Public — Public profile changes are most suspicious |
| Rule ID | Unique rule identifier |
| Subject: Account Name | Who created the rule |
| Rule Information | Port, protocol, direction, action embedded in the message |

### PowerShell Detection

```powershell
# Find all new firewall rules
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4946
    StartTime = (Get-Date).AddDays(-7)
} | Select-Object TimeCreated, Message | Format-List
```
---

<img width="515" height="344" alt="Screenshot_13" src="https://github.com/user-attachments/assets/21b9563c-ebef-4486-b656-490a3c844fd0" />

---


```powershell
# Alert on inbound allow rules — highest priority variant
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4946
    StartTime = (Get-Date).AddDays(-7)
} | Where-Object {
    $_.Message -like "*Inbound*" -and $_.Message -like "*Allow*"
} | ForEach-Object {
    Write-Host "=== NEW INBOUND ALLOW RULE ADDED ===" -ForegroundColor Red
    Write-Host "Time    : $($_.TimeCreated)"
    Write-Host "Details : $($_.Message)"
    Write-Host ""
}
```

---

## SOC Analyst Notes

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Known software installer adding rule during business hours |
| 🟡 Medium | Admin adding rule outside documented change window |
| 🔴 High | Inbound Allow rule on unusual port from PowerShell process |
| 🔴 Critical | Inbound Allow rule from unknown process, off-hours, unusual port |

### MITRE ATT&CK Reference

- **T1562.004** — Impair Defenses: Disable or Modify System Firewall
- **T1071** — Application Layer Protocol (opening port for C2)
