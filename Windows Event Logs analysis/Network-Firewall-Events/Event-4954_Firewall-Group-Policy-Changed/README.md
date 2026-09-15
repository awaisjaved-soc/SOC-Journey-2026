# Event ID 4954 — Firewall Group Policy Changed

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
| Event ID | 4954 |
| Event Name | Windows Firewall Group Policy settings have changed — the new settings have been applied |
| Log Location | Windows Logs → Security |
| Audit Subcategory | MPSSVC Rule-Level Policy Change |
| Default State | Disabled — must be manually enabled |
| SACL Required | No |
| Volume | Low — fires when Group Policy firewall settings are applied |
| Where It Fires | On every machine that receives the changed Group Policy |

---

## What Is Event 4954?

Event 4954 fires when Windows Firewall settings are changed through Group Policy and the new policy is applied to the machine. This is the most impactful firewall event in this category because Group Policy changes can affect every single machine in the domain simultaneously.

While 4946, 4947, and 4948 track individual rule changes on a single machine, 4954 tracks policy-level changes that propagate across the entire organisation. An attacker with Domain Admin or Group Policy modification rights who changes the domain firewall policy has potentially modified the firewall configuration of every computer in the domain in a single action.

### What Makes 4954 So Significant

The blast radius is the key difference. When an attacker adds a firewall rule locally on one machine, only that machine is affected. When they modify the domain Group Policy firewall settings, every domain-joined machine that applies that policy is affected. A single change can:

- Disable the firewall entirely across the whole domain
- Add allow rules to every machine simultaneously
- Remove blocking rules from every machine at once
- Change firewall profiles from restrictive to permissive for all computers

Event 4954 fires on each individual machine when it receives and applies the updated Group Policy — so in a 500-machine domain, one malicious GPO change would generate 500 4954 events across the environment, one per machine. A SIEM that collects from all machines would show a sudden burst of 4954 events — that burst is itself alertable.

---

## Audit Policy Setup

```cmd
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
```

Run this on all machines or deploy via Group Policy.

---

<img width="474" height="334" alt="Screenshot_3" src="https://github.com/user-attachments/assets/5ad90ccf-9caf-4340-9fda-b3763dc6889d" />

---

## Generating the Event

### Method 1 — Force Group Policy Refresh

If firewall settings exist in any GPO applied to your machine, forcing a refresh will apply them and generate 4954:

```powershell
# Force Group Policy update — generates 4954 if firewall policy exists in GPO
gpupdate /force
Write-Host "Group Policy updated. Check Security log for Event 4954." -ForegroundColor Yellow
```
---


### Method 2 — Modify Firewall Policy via GPO (Domain Controller)

1. Log in to the **Domain Controller**
2. Open **Group Policy Management** (`gpmc.msc`)
3. Edit **Default Domain Policy**
4. Navigate to: `Computer Configuration → Policies → Windows Settings → Security Settings → Windows Defender Firewall with Advanced Security`
5. Modify any firewall setting — change a profile state or add a rule
6. Close the editor
7. On a member machine run `gpupdate /force`
8. Check that machine's Security log for Event 4954

---

<img width="313" height="179" alt="Screenshot_1" src="https://github.com/user-attachments/assets/1f804f70-acf0-48c5-b5e2-723ca3d21bed" />

---


<img width="952" height="479" alt="Screenshot_10" src="https://github.com/user-attachments/assets/43bc6dff-ed85-4766-82f5-f860de61ad69" />

---

### Method 3 — Disable and Re-enable a Firewall Profile via PowerShell

```powershell
# Temporarily change firewall profile setting — generates 4954
Set-NetFirewallProfile -Profile Domain -Enabled False
Write-Host "Domain firewall profile disabled — Event 4954 may fire." -ForegroundColor Red
Start-Sleep -Seconds 2

# Re-enable immediately
Set-NetFirewallProfile -Profile Domain -Enabled True
Write-Host "Domain firewall profile re-enabled." -ForegroundColor Green
```

---

## Detecting the Event

### GUI — Event Viewer

1. Event Viewer → Windows Logs → **Security**
2. Filter → Event ID: `4954` → OK
3. Each entry represents a Group Policy firewall change being applied

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Date and Time | When the policy was applied |
| Computer Name | Which machine applied the new policy |
| Profile | Which firewall profile was affected |

---

<img width="522" height="211" alt="Screenshot_4" src="https://github.com/user-attachments/assets/3fd2336d-b13f-4bb0-bd8f-e8629f9bf258" />

---

<img width="474" height="334" alt="Screenshot_3" src="https://github.com/user-attachments/assets/00396d7c-317c-46a1-8106-b9b2a703ec03" />

---


### PowerShell Detection

```powershell
# Find all Group Policy firewall change events
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4954
    StartTime = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message |
    Format-List
```
---

<img width="678" height="385" alt="Screenshot_2" src="https://github.com/user-attachments/assets/37e07c82-3410-49c4-926b-fad1c9b68fd1" />

---


```powershell
# Count 4954 events per day — spike detection
# A sudden burst of 4954 events across machines = domain-wide GPO change
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4954
    StartTime = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Group-Object { $_.TimeCreated.Date.ToString("yyyy-MM-dd") } |
    Select-Object Name, Count |
    Sort-Object Name |
    Format-Table -AutoSize
```

```powershell
# Combined firewall rule event report — all four events together
Write-Host "=== COMPLETE FIREWALL CHANGE REPORT ===" -ForegroundColor Cyan

@(4946, 4947, 4948, 4954) | ForEach-Object {
    $eventId = $_
    $count = (Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = $eventId
        StartTime = (Get-Date).AddDays(-7)
    } -ErrorAction SilentlyContinue).Count

    $label = switch ($eventId) {
        4946 { "Rule Added    (4946)" }
        4947 { "Rule Modified (4947)" }
        4948 { "Rule Deleted  (4948)" }
        4954 { "GPO Changed   (4954)" }
    }
    Write-Host "$label : $count events"
}
```

---

## SOC Analyst Notes

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | 4954 after known patch Tuesday or documented GPO change |
| 🟡 Medium | 4954 on multiple machines outside maintenance window |
| 🔴 High | 4954 burst across many machines — domain-wide policy change |
| 🔴 Critical | 4954 following firewall profile being disabled — entire domain exposed |

### MITRE ATT&CK Reference

- **T1562.004** — Impair Defenses: Disable or Modify System Firewall
- **T1484.001** — Domain Policy Modification: Group Policy Modification
