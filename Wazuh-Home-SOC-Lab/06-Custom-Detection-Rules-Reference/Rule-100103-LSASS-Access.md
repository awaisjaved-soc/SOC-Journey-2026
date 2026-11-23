# Rule 100103 — Possible Credential Dumping (Process Opened LSASS)

*Part of [Custom Detection Rules — Master Reference](README.md). Status: **TESTED & VERIFIED** (Lab 15).*

| Field | Value |
|---|---|
| Rule ID | 100103 |
| Level | 12 |
| Event | Sysmon event 10 (ProcessAccess), target image `lsass.exe` |
| MITRE | **T1003.001** — OS Credential Dumping: LSASS Memory |
| Group | `credential_access` |
| Source | Rule pack (`local_rules.xml`, 100100–100108, 100127) |
| Live Verification | **Verified Live** in [Lab 15 — LSASS Ticket Stealing & Memory Dumping](../01-Core-Detection-Labs/02-Kerberos-Attacks-and-Defense-Labs/15-LSASS-Ticket-Stealing-and-Memory-Dumping/) |

## Rule

```xml
<rule id="100103" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^10$</field>
  <field name="win.eventdata.targetImage">lsass\.exe$</field>
  <description>Possible credential dumping: process opened LSASS (Sysmon event 10)</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
  <group>credential_access,</group>
</rule>
```

## What it detects

A process opening **LSASS** (Local Security Authority Subsystem Service) — the process that holds credentials and in-memory Kerberos tickets in RAM. Sysmon event 10 (ProcessAccess) records it. This is the Mimikatz / Procdump pattern: read LSASS memory to extract passwords, hashes, and Kerberos TGTs.

## Purpose

LSASS holds the keys to the domain: every password, hash, and Kerberos ticket that has been used on the machine passes through it. There is almost no legitimate reason for an unauthorized process to open LSASS memory with read privileges — the processes that do it are credential-dumping tools. Level 12 expresses that this is an active credential-theft attempt, not a routine logon anomaly.

## How it works

- **`<if_group>windows</if_group>`** — only events decoded by the Windows decoder are evaluated.
- **`<field name="win.system.eventID">^10$</field>`** — the event must be Sysmon event **10** (ProcessAccess) arriving on `Microsoft-Windows-Sysmon/Operational`.
- **`<field name="win.eventdata.targetImage">lsass\.exe$</field>`** — the process being accessed must be `lsass.exe`. Any other target image does not match.
- **Level 12** — high severity alert, because LSASS access is the microsecond immediately before credential extraction.

## Production Tuning & Child Rule (Rule 100127)

During live deployment in Lab 15, an un-tuned Rule 100103 produced an alert storm of **775 false positives** due to `VBoxService.exe` (VirtualBox Guest Additions) polling user session status every 10–15 seconds with access mask `0x1400` (`PROCESS_QUERY_INFORMATION`).

To eliminate alert fatigue without disabling the detection, child rule **[Rule 100127](Rule-100127-LSASS-VBoxService-Tuning.md)** was deployed at Level 0:

```xml
<rule id="100127" level="0">
  <if_sid>100103</if_sid>
  <field name="win.eventdata.sourceImage">VBoxService\.exe$</field>
  <field name="win.eventdata.grantedAccess">^0x1400$</field>
  <description>Tuning: Suppress benign VirtualBox Guest Additions status queries to LSASS</description>
</rule>
```

## Test Evidence (Verified Live in Lab 15)

- **Platform:** Windows Server 2022 Datacenter (`WIN-SOCLAB`) + Wazuh 4.14.5 SIEM (`192.168.100.50`).
- **Telemetry Source:** Sysmon v15.22 kernel driver with targeted filter:
  `<ProcessAccess onmatch="include"><TargetImage condition="end with">lsass.exe</TargetImage></ProcessAccess>`.
- **Negative Test:** 8-minute complete silence after deploying tuning Rule 100127 (775 alert storm dropped to 0).
- **Positive Test:** Executing `taskmgr.exe` triggered an immediate Level 12 alert on `Rule 100103`:
  - `SourceImage`: `C:\Windows\system32\Taskmgr.exe`
  - `TargetImage`: `C:\Windows\system32\lsass.exe`
  - `GrantedAccess`: `0x1400`
  - `User`: `SOCLAB\Administrator`

![Rule 100103 Firing Evidence](../01-Core-Detection-Labs/02-Kerberos-Attacks-and-Defense-Labs/15-LSASS-Ticket-Stealing-and-Memory-Dumping/images/07_wazuh_taskmgr_document_details_level12.jpg)

## Find it in Wazuh

```
rule.id: 100103
```

## MITRE ATT&CK

**T1003.001 — OS Credential Dumping: LSASS Memory.** Adversaries access LSASS process memory to extract credentials — passwords, hashes, and Kerberos tickets. One LSASS read can yield every credential active on the machine.
