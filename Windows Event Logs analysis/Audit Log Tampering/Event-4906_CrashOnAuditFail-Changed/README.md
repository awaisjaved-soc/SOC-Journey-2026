# Event ID 4906 — CrashOnAuditFail Value Changed

**Log:** Security  
**Category:** Policy Change  
**Subcategory:** Other Policy Change Events  
**Level:** Information  
**Lab Environment:** Windows Server 2022 — TECHCORP / techcorp.local  
**Lab Status:** ✅ Successfully Generated

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 4906 |
| Event Name | The CrashOnAuditFail value has changed |
| Log Location | Windows Logs → Security |
| Audit Category | Policy Change |
| Audit Subcategory | Other Policy Change Events |
| Registry Location | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\CrashOnAuditFail` |
| Default State | Fires automatically when registry value changes |
| SACL Required | No |

---

## What Is Event 4906?

Event 4906 fires when the `CrashOnAuditFail` registry value is changed. This is one of the most obscure events in this category but understanding it reveals a clever attacker technique for blinding Windows logging without triggering the obvious indicators like 1102 or 1100.

### Understanding CrashOnAuditFail

Windows has a built-in security feature designed for high-security environments. The question it answers is:

> What should Windows do if the Security log becomes completely full and cannot write new audit events?

By default (value = 0), Windows silently drops new audit events when the log is full. The system keeps running, users notice nothing, but security events stop being recorded. An attacker who fills the Security log with noise — thousands of rapid authentication attempts, for example — can cause legitimate audit events to be silently dropped without any visible indication.

| Value | Behaviour |
|---|---|
| `0` | Default — new events silently dropped when log is full |
| `1` | System crashes (BSOD) if log cannot be written — ensures no unlogged actions |
| `2` | Special locked state — only Administrators can log in (set automatically after a crash) |

### How Attackers Abuse This Setting

A sophisticated attacker who knows about this feature may use a two-step approach:

**Step 1:** Change `CrashOnAuditFail` from 1 to 0 — Event 4906 fires but this is obscure and may not immediately alert anyone.

**Step 2:** Flood the Security log with high-volume events until it fills completely. With the default value of 0, new audit events are silently dropped. The attacker now has a window to perform actions with no logging.

The reason they change it from 1 to 0 first is because if the setting were at 1 and they filled the log, the system would crash — giving them a BSOD instead of a blind spot. Disabling the crash protection first ensures the silent drop behaviour when the log fills.

This technique is rare in real attacks but demonstrates the depth of knowledge that APT groups apply to evading detection.

---

## Audit Policy Setup

```cmd
auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable
```

---

## Generating the Event

### GUI Method

1. Open **Registry Editor** (`regedit`) as Administrator
2. Navigate to: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`
3. Look for `CrashOnAuditFail` in the right panel
4. If it does not exist: right-click empty space → **New** → **DWORD (32-bit) Value** → name it `CrashOnAuditFail`
5. Double-click it → change value to `1` → OK
6. Event 4906 fires immediately
7. Change it back to `0` after taking your screenshot

### PowerShell Method

```powershell
# Check current value
$current = Get-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "CrashOnAuditFail" `
    -ErrorAction SilentlyContinue

Write-Host "Current CrashOnAuditFail value: $($current.CrashOnAuditFail)"

# Change to 1 — generates Event 4906
Set-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "CrashOnAuditFail" `
    -Value 1
Write-Host "Value changed to 1 — Event 4906 fired." -ForegroundColor Yellow
Write-Host "Take screenshot now, then restore." -ForegroundColor Cyan

Start-Sleep -Seconds 3

# Restore to 0
Set-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "CrashOnAuditFail" `
    -Value 0
Write-Host "Restored to 0 — second Event 4906 fired for the restoration." -ForegroundColor Green
```

---

## Detecting the Event

### GUI — Event Viewer

1. Event Viewer → Windows Logs → **Security**
2. Filter → Event ID: `4906` → OK
3. Each entry shows the new value that was set

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| New Value | What CrashOnAuditFail was changed to — 0 is the suspicious change |
| Subject: Account Name | Who made the change |
| Date and Time | When it was changed — correlate with log flooding attempts |

### PowerShell Detection

```powershell
# Find CrashOnAuditFail changes
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4906
    StartTime = (Get-Date).AddDays(-30)
} | Select-Object TimeCreated, Message | Format-List
```

```powershell
# Check current registry value
$val = Get-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "CrashOnAuditFail" `
    -ErrorAction SilentlyContinue

if ($val) {
    Write-Host "CrashOnAuditFail current value: $($val.CrashOnAuditFail)"
    if ($val.CrashOnAuditFail -eq 0) {
        Write-Host "Value is 0 — log will silently drop events when full." -ForegroundColor Yellow
    }
} else {
    Write-Host "CrashOnAuditFail not set — default behaviour (0)." -ForegroundColor Yellow
}
```

---

## SOC Analyst Notes

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Value changed from 0 to 1 — security is being strengthened |
| 🟡 Medium | Value changed from 1 to 0 — crash protection removed |
| 🔴 High | Value changed to 0 followed by high-volume log activity |
| 🔴 Critical | Value changed to 0 then log fills and events stop — active blinding in progress |

### MITRE ATT&CK Reference

- **T1562.002** — Impair Defenses: Disable Windows Event Logging
- **T1562.001** — Impair Defenses: Disable or Modify Tools
