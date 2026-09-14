# Event ID 4947 — Firewall Rule Modified

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
| Event ID | 4947 |
| Event Name | A change has been made to Windows Firewall exception list — a rule was modified |
| Log Location | Windows Logs → Security |
| Audit Subcategory | MPSSVC Rule-Level Policy Change |
| Default State | Disabled — must be manually enabled |
| SACL Required | No |
| Volume | Low — only fires when an existing rule is changed |

---

## What Is Event 4947?

Event 4947 fires when an existing Windows Firewall rule is modified — its scope changed, action changed, ports altered, or any other property updated. While Event 4946 catches brand new rules being created, 4947 catches existing rules being quietly expanded or changed.

This is a subtler and often more dangerous technique than simply adding a new rule. An attacker who creates a new inbound Allow rule generates 4946 — which is easy to spot as something new appearing. But an attacker who modifies an existing, legitimate-looking rule to expand its scope flies under the radar because the rule was already there. The change is less visible unless someone is specifically watching for 4947.

### The Scope Expansion Attack

A common pattern is:

```
Legitimate rule exists: Allow inbound TCP on port 8080 from internal network only
        ↓
Attacker modifies the rule's remote address from internal subnet to "Any"
        ↓
Event 4947 fires — rule was modified
        ↓
Now the rule allows inbound connections from ANYWHERE on port 8080
        ↓
Attacker connects from their external server
```

The rule still has the same name and looks legitimate at a glance. Only a careful review of the rule's properties — or a 4947 event alerting you to the change — reveals the modification.

---

## Audit Policy Setup

```cmd
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
```

---

## Generating the Event

### PowerShell Method

```powershell
# Step 1: Create a base rule to modify
New-NetFirewallRule `
    -DisplayName "SOC-Lab-Modify-Test" `
    -Direction Outbound `
    -Protocol TCP `
    -RemotePort 8080 `
    -Action Allow
Write-Host "Base rule created on port 8080." -ForegroundColor Green

Start-Sleep -Seconds 2

# Step 2: Modify the rule — simulates attacker expanding scope
# Adding ports 9090 and 4444 alongside the original 8080
Set-NetFirewallRule `
    -DisplayName "SOC-Lab-Modify-Test" `
    -RemotePort 8080,9090,4444
Write-Host "Rule modified to include ports 9090 and 4444 — Event 4947 fired." -ForegroundColor Yellow

Start-Sleep -Seconds 2

# Step 3: Clean up
Remove-NetFirewallRule -DisplayName "SOC-Lab-Modify-Test"
Write-Host "Rule removed." -ForegroundColor Green
```

### GUI Method

1. Open `wf.msc` → find any existing rule
2. Double-click it to open Properties
3. Change any setting — port range, scope, remote address
4. Click OK → Event 4947 fires immediately
5. Revert the change after screenshot

---

## Detecting the Event

### GUI — Event Viewer

1. Event Viewer → Windows Logs → **Security**
2. Filter → Event ID: `4947` → OK

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Rule Name | Which existing rule was modified |
| Profile Used | Which firewall profile was affected |
| Subject: Account Name | Who modified the rule |
| Rule ID | Unique rule identifier — look up the rule by this ID |

### PowerShell Detection

```powershell
# Find all rule modifications
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4947
    StartTime = (Get-Date).AddDays(-7)
} | Select-Object TimeCreated, Message | Format-List
```

```powershell
# Correlate 4946 and 4947 together — full picture of firewall changes
Write-Host "=== FIREWALL RULE CHANGES ===" -ForegroundColor Cyan

Write-Host "New Rules Added (4946):" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4946
    StartTime = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Format-List

Write-Host "Rules Modified (4947):" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4947
    StartTime = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Format-List
```

---

## SOC Analyst Notes

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Known admin modifying rule scope during documented maintenance |
| 🟡 Medium | Rule modification outside business hours |
| 🔴 High | Existing block rule changed to Allow |
| 🔴 Critical | Rule scope expanded from internal-only to Any — exposes port to internet |

### MITRE ATT&CK Reference

- **T1562.004** — Impair Defenses: Disable or Modify System Firewall
