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

### Command Line Method

```cmd
:: Disable process creation auditing — simulates attacker hiding process activity
auditpol /set /subcategory:"Process Creation" /success:disable

:: Event 4719 fires — take screenshot now

:: Re-enable immediately
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

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

## Detecting the Event

### GUI — Event Viewer

1. Event Viewer → Windows Logs → **Security**
2. Filter Current Log → Event ID: `4719` → OK
3. Look for clusters of events — a burst at one timestamp indicates a policy refresh
4. Look for individual events — a single 4719 at an unusual time is more suspicious

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
