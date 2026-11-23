# Rule 100127 — Critical: Suspicious Memory Read Rights Requested on LSASS

*Part of [Custom Detection Rules — Master Reference](README.md). Status: **DEPLOYED & ARMED** (Tier 2 Weaponized Detector).*

| Field | Value |
|---|---|
| Rule ID | 100127 |
| Level | 12 (Critical High-Severity Alert) |
| Event | Sysmon event 10 (ProcessAccess), target `lsass.exe`, `GrantedAccess` includes `VM_READ` |
| MITRE | **T1003.001** — OS Credential Dumping: LSASS Memory |
| Group | `credential_access` |
| Parent Rule | `100103` (`<if_sid>100103</if_sid>`) |
| Architecture Tier | **Tier 2: Weaponized Memory Read Threat Detector** |

## Rule

```xml
<rule id="100127" level="12">
  <if_sid>100103</if_sid>
  <field name="win.eventdata.grantedAccess">0x1010|0x1410|0x1fffff|0x0010</field>
  <description>CRITICAL: Potential Credential Dumping - Memory Read Rights Requested on LSASS (Sysmon event 10)</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
  <group>credential_access,</group>
</rule>
```

## What it detects

Any process requesting explicit **Memory Read permissions (`PROCESS_VM_READ` / `0x0010`)** against **LSASS**. 

Under Windows Win32 API security, memory-dumping and credential-theft tools (e.g., Mimikatz `sekurlsa::tickets`, Procdump, Nanodump, Comsvcs) cannot extract passwords, hashes, or in-memory Kerberos tickets without `PROCESS_VM_READ`.

## Purpose & Why This Solves Alert Fatigue

Unlike raw handle rules that alert on routine status queries (`0x1000` or `0x1400`), this rule evaluates the **adversary's capability and intent**:
- Legitimate background daemons (`svchost.exe`, `VBoxService.exe`, `Taskmgr.exe`) only request query rights (`0x1000` / `0x1400`). They fall back to Tier 1 Rule 100103 (Level 3) and generate zero alerts.
- Any process attempting to read LSASS virtual memory must request a bitmask containing `0x0010` (such as `0x1010`, `0x1410`, or `0x1fffff`). Rule 100127 intercepts this instantly and fires a **Level 12 Critical Alarm** on the SOC dashboard.

## How it works

- **`<if_sid>100103</if_sid>`** — Chains directly to parent Rule 100103 (any handle to `lsass.exe`).
- **`<field name="win.eventdata.grantedAccess">0x1010|0x1410|0x1fffff|0x0010</field>`** — Evaluates the hexadecimal access rights bitmask:
  - `0x0010` = `PROCESS_VM_READ`
  - `0x1010` = `PROCESS_QUERY_LIMITED_INFORMATION` | `PROCESS_VM_READ`
  - `0x1410` = `PROCESS_QUERY_INFORMATION` | `PROCESS_VM_READ`
  - `0x1fffff` = `PROCESS_ALL_ACCESS`
- **`level="12"`** — High-severity alert paging the on-call incident response team.

## Find it in Wazuh

```
rule.id: 100127
```
