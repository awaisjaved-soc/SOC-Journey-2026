# Event ID 4948 — Firewall Rule Deleted

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
| Event ID | 4948 |
| Event Name | A change has been made to Windows Firewall exception list — a rule was deleted |
| Log Location | Windows Logs → Security |
| Audit Subcategory | MPSSVC Rule-Level Policy Change |
| Default State | Disabled — must be manually enabled |
| SACL Required | No |
| Volume | Low — only fires when a rule is deleted |

---

## What Is Event 4948?

Event 4948 fires when an existing Windows Firewall rule is deleted. While 4946 and 4947 track rules being added or changed, 4948 tracks rules being removed — which in a security context often means something that was protecting the system has been taken away.

Deleting a firewall rule has a different effect than adding a new Allow rule. When you add an Allow rule (4946), you explicitly permit something that was previously not explicitly permitted. When you delete a Block rule (4948), you remove a protection that was previously in place — traffic that was being stopped will now reach its destination. This is often a more subtle and effective technique.

### The Delete-to-Expose Attack

```
Security team has a block rule: Block all inbound on port 445 (SMB) from external
        ↓
Attacker deletes the block rule
        ↓
Event 4948 fires
        ↓
Port 445 is now exposed — no explicit block rule exists
        ↓
Attacker can attempt SMB connection from external IP
```

No new Allow rule was added. Nothing looks explicitly suspicious to someone just checking the Allow rules list. Only the deletion event (4948) and a careful review of the rule inventory reveals that a protection was removed.

---

## Audit Policy Setup

```cmd
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
```

---

## Generating the Event

### PowerShell Method

```powershell
# Step 1: Create a rule to delete
New-NetFirewallRule `
    -DisplayName "SOC-Lab-Delete-Test" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 6666 `
    -Action Block
Write-Host "Block rule created on port 6666." -ForegroundColor Green

Start-Sleep -Seconds 2

# Step 2: Delete it — generates Event 4948
Remove-NetFirewallRule -DisplayName "SOC-Lab-Delete-Test"
Write-Host "Block rule deleted — Event 4948 generated." -ForegroundColor Red
Write-Host "Port 6666 is no longer explicitly blocked." -ForegroundColor Yellow
```

### GUI Method

1. Open `wf.msc`
2. Create a temporary test rule (or use an existing non-critical rule)
3. Right-click the rule → **Delete**
4. Confirm deletion → Event 4948 fires immediately

---

## Detecting the Event

### GUI — Event Viewer

1. Event Viewer → Windows Logs → **Security**
2. Filter → Event ID: `4948` → OK

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Rule Name | Which rule was deleted — look up what it was blocking |
| Profile Used | Domain/Private/Public |
| Subject: Account Name | Who deleted the rule |
| Rule ID | Use this to cross-reference what the rule was doing before deletion |

### PowerShell Detection

```powershell
# Find all rule deletions
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4948
    StartTime = (Get-Date).AddDays(-7)
} | Select-Object TimeCreated, Message | Format-List
```

```powershell
# Full firewall change summary — add, modify, delete together
Write-Host "=== FIREWALL RULE CHANGE SUMMARY (Last 24 Hours) ===" -ForegroundColor Cyan
Write-Host ""

$added    = (Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4946; StartTime=(Get-Date).AddDays(-1) } -ErrorAction SilentlyContinue).Count
$modified = (Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4947; StartTime=(Get-Date).AddDays(-1) } -ErrorAction SilentlyContinue).Count
$deleted  = (Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4948; StartTime=(Get-Date).AddDays(-1) } -ErrorAction SilentlyContinue).Count

Write-Host "Rules Added    (4946): $added"    -ForegroundColor Yellow
Write-Host "Rules Modified (4947): $modified" -ForegroundColor Yellow
Write-Host "Rules Deleted  (4948): $deleted"  -ForegroundColor Red

if ($deleted -gt 0) {
    Write-Host ""
    Write-Host "WARNING: $deleted rule(s) deleted — verify these were authorized." -ForegroundColor Red
}
```

---

## SOC Analyst Notes

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Admin removing outdated or duplicate rule — documented change |
| 🟡 Medium | Rule deletion outside business hours |
| 🔴 High | Block rule deleted — protection removed from specific port or process |
| 🔴 Critical | Critical security rule deleted (e.g. SMB block, RDP restriction) from unknown account |

### MITRE ATT&CK Reference

- **T1562.004** — Impair Defenses: Disable or Modify System Firewall
- **T1021.002** — Remote Services: SMB/Windows Admin Shares (blocking rule removal enables this)
