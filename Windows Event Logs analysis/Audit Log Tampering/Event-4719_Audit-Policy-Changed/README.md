# Event ID 4719 — System Audit Policy Changed

**Log:** Security  
**Category:** Policy Change  
**Subcategory:** Audit Policy Change  
**Level:** Information  
**Lab Environment:** Windows Server 2022 — TECHCORP / techcorp.local  
**Lab Status:** ✅ Successfully Generated

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 4719 |
| Event Name | System audit policy was changed |
| Log Location | Windows Logs → Security |
| Audit Category | Policy Change |
| Audit Subcategory | Audit Policy Change |
| Default State | Enabled by default on Windows Server |
| SACL Required | No |

---

<img width="471" height="329" alt="Screenshot_7" src="https://github.com/user-attachments/assets/a7846950-68aa-4398-a10f-361f7814485c" />

---



## What Is Event 4719?

Event 4719 fires whenever the system audit policy is modified — meaning someone used `auditpol`, Group Policy, or the Local Security Policy editor to change which events Windows logs. Every time a subcategory is enabled, disabled, or changed, a 4719 event is written recording exactly what changed.

This is one of the most surgical anti-forensics techniques available to sophisticated attackers. Instead of clearing the entire Security log (which generates the obvious Event 1102 and immediately alerts defenders), a skilled attacker disables only the specific audit subcategory that would catch their next planned action. The attack happens, no events are generated, and the attacker re-enables the policy. Two 4719 events appear — one for the disable, one for the re-enable — but the malicious activity between them is invisible.

### The Surgical Blinding Technique

Consider this attack sequence:

```
Attacker wants to install a malicious service
→ Runs: auditpol /set /subcategory:"Security System Extension" /success:disable
→ Event 4719 fires (policy disabled)
→ Installs malicious service
→ Events 7045 and 4697 do NOT fire (auditing is off)
→ Runs: auditpol /set /subcategory:"Security System Extension" /success:enable
→ Event 4719 fires (policy re-enabled)
```

The SOC sees two 4719 events and a suspicious gap. A defender who understands 4719 knows to ask: what happened between those two policy changes?

### Lab Observation — Multiple 4719 Events

When you changed a single audit policy in the lab, you likely saw many 4719 events appear almost simultaneously. This is normal Windows behaviour. When an audit policy is refreshed — especially through Group Policy — Windows writes a 4719 event for every subcategory that was evaluated, not just the one you explicitly changed. The cluster of 4719 events at the same timestamp indicates a policy refresh, not multiple individual changes.

---

## Audit Policy Setup

```cmd
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
```

Verify:

```cmd
auditpol /get /subcategory:"Audit Policy Change"
```

---



## Generating the Event

### GUI Method

1. Open **Local Security Policy** (`secpol.msc`) as Administrator
2. Navigate to: `Security Settings → Advanced Audit Policy Configuration → System Audit Policies → Object Access`
3. Double-click any subcategory
4. Change the setting — for example uncheck **Success** on **Audit Process Creation**
5. Click OK → Apply
6. Event 4719 fires
7. Revert the change immediately after screenshot

---

<img width="953" height="478" alt="Screenshot_1" src="https://github.com/user-attachments/assets/106d9a80-bc42-49a6-a255-930bec88bc57" />

---

<img width="960" height="488" alt="Screenshot_2" src="https://github.com/user-attachments/assets/4e904aa2-bb55-4e69-b008-6fed39e33271" />

---

<img width="627" height="312" alt="Screenshot_3" src="https://github.com/user-attachments/assets/2b38d47f-8201-4b9d-903e-2a9a4bd97210" />

---

<img width="957" height="481" alt="Screenshot_4" src="https://github.com/user-attachments/assets/66bc10e6-1eca-49ba-a0de-56dd0d3d6d4c" />

---

### Command Line Method

```cmd
:: Disable process creation auditing — simulates attacker hiding process activity
auditpol /set /subcategory:"Process Creation" /success:disable

:: Event 4719 fires — take screenshot now

:: Re-enable immediately
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```
---


<img width="472" height="329" alt="Screenshot_5" src="https://github.com/user-attachments/assets/5ada3f56-ad7a-44ad-9cb5-d111e7fe3951" />

---


### PowerShell Method

```powershell
Write-Host "Simulating audit policy tampering..." -ForegroundColor Yellow

# Disable — generates 4719
& auditpol /set /subcategory:"Process Creation" /success:disable
Write-Host "Audit policy disabled — Event 4719 fired." -ForegroundColor Red

Start-Sleep -Seconds 2

# Re-enable — generates another 4719
& auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Write-Host "Audit policy restored — second 4719 fired." -ForegroundColor Green
```

---

<img width="633" height="280" alt="Screenshot_6" src="https://github.com/user-attachments/assets/b274a243-f93c-437b-9d66-be35d0a96df5" />

---


## Detecting the Event

### GUI — Event Viewer

1. Event Viewer → Windows Logs → **Security**
2. Filter Current Log → Event ID: `4719` → OK
3. Look for clusters of events — a burst at one timestamp indicates a policy refresh
4. Look for individual events — a single 4719 at an unusual time is more suspicious

---

<img width="471" height="329" alt="Screenshot_7" src="https://github.com/user-attachments/assets/567031ec-932a-4324-acf6-09f1b18dfaca" />

---


<img width="470" height="331" alt="Screenshot_8" src="https://github.com/user-attachments/assets/950a9591-7abc-4bf1-827c-d7ba28ae6336" />

---


**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Subject: Account Name | Who changed the policy |
| Subcategory | Which specific audit category was modified |
| Subcategory GUID | Unique identifier for the changed subcategory |
| Changes | `%%8448` = No Auditing (most suspicious) / `%%8449` = Success / `%%8450` = Failure |
| Old Value | What the setting was before |
| New Value | What it was changed to |

### PowerShell Detection

```powershell
# All audit policy changes in last 7 days
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4719
    StartTime = (Get-Date).AddDays(-7)
} | Select-Object TimeCreated, Message | Format-List
```
---

<img width="679" height="367" alt="Screenshot_9" src="https://github.com/user-attachments/assets/cd14d623-7df5-425d-8b29-887664832828" />

---


```powershell
# Hunt specifically for audit policies being DISABLED — most suspicious
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4719
    StartTime = (Get-Date).AddDays(-7)
} | Where-Object {
    $_.Message -like "*No Auditing*" -or $_.Message -like "*%%8448*"
} | ForEach-Object {
    Write-Host "=== AUDIT POLICY DISABLED ===" -ForegroundColor Red
    Write-Host "Time    : $($_.TimeCreated)"
    Write-Host "Details : $($_.Message)"
    Write-Host ""
}
```

```powershell
# Check current state of all audit policies
& auditpol /get /category:*
```

---

## SOC Analyst Notes

### Decoding the Changes Field

| Code | Meaning | Suspicion Level |
|---|---|---|
| `%%8448` | No Auditing — disabled completely | 🔴 High |
| `%%8449` | Success auditing enabled | 🟢 Normal |
| `%%8450` | Failure auditing enabled | 🟢 Normal |
| `%%8451` | Success and Failure enabled | 🟢 Normal |

When you see `%%8448` — something was turned off. Ask immediately: what did the attacker not want you to see?

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Large cluster of 4719 at same time — Group Policy refresh, normal |
| 🟡 Medium | Single 4719 from admin account during business hours |
| 🔴 High | 4719 disabling specific subcategory followed by suspicious activity |
| 🔴 Critical | 4719 pair (disable then re-enable) with no events in between — surgical blinding |

### MITRE ATT&CK Reference

- **T1562.002** — Impair Defenses: Disable Windows Event Logging
- **T1562.001** — Impair Defenses: Disable or Modify Tools
