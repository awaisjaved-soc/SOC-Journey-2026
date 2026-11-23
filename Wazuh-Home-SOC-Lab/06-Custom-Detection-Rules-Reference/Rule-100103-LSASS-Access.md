# Rule 100103 — Base Telemetry: Process Opened LSASS (Sysmon Event 10)

*Part of [Custom Detection Rules — Master Reference](README.md). Status: **TESTED & VERIFIED** (Lab 15).*

| Field | Value |
|---|---|
| Rule ID | 100103 |
| Level | 3 (Informational / Base Audit Telemetry) |
| Event | Sysmon event 10 (ProcessAccess), target image `lsass.exe` |
| MITRE | **T1003.001** — OS Credential Dumping: LSASS Memory |
| Group | `credential_access` |
| Source | Rule pack (`local_rules.xml`, 100100–100108, 100127) |
| Architecture Tier | **Tier 1: Base Telemetry Collector** |
| Live Verification | **Verified Live** in [Lab 15 — LSASS Ticket Stealing & Memory Dumping](../01-Core-Detection-Labs/02-Kerberos-Attacks-and-Defense-Labs/15-LSASS-Ticket-Stealing-and-Memory-Dumping/) |

## Rule

```xml
<rule id="100103" level="3">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^10$</field>
  <field name="win.eventdata.targetImage">lsass\.exe$</field>
  <description>Audit: Process requested handle to LSASS (Sysmon event 10)</description>
  <group>credential_access,</group>
</rule>
```

## What it detects

Any process opening a handle to **LSASS** (Local Security Authority Subsystem Service) — the process that holds credentials and in-memory Kerberos tickets in RAM. Sysmon event 10 (ProcessAccess) records it.

## Architectural Purpose (Why Level 3?)

In enterprise environments, standard Windows system components (such as `svchost.exe`, `csrss.exe`) and hypervisor integration services (`VBoxService.exe`, `vmtoolsd.exe`) routinely query LSASS properties using read-only status access masks (`0x1000` or `0x1400`). 

Configuring this base rule at **Level 3 (Informational / Audit)** ensures that:
1. **Zero Alert Fatigue:** Routine status queries are indexed silently without triggering false-positive alerts on the SOC dashboard.
2. **Full Forensic Visibility:** Every handle opened to LSASS is preserved for threat hunting and incident timeline reconstruction.
3. **Parent for Critical Detections:** Serves as the foundation for **[Rule 100127](Rule-100127-LSASS-Memory-Read-Detection.md) (Level 12)**, which fires only when suspicious memory read permissions (`PROCESS_VM_READ`) are requested.

## How it works

- **`<if_group>windows</if_group>`** — Only events decoded by the Windows decoder are evaluated.
- **`<field name="win.system.eventID">^10$</field>`** — The event must be Sysmon event **10** (ProcessAccess) arriving on `Microsoft-Windows-Sysmon/Operational`.
- **`<field name="win.eventdata.targetImage">lsass\.exe$</field>`** — The process being accessed must be `lsass.exe`.
- **`level="3"`** — Logs the event quietly for forensic history without alerting on-call personnel.

## Test Evidence (Verified Live in Lab 15)

- **Platform:** Windows Server 2022 Datacenter (`WIN-SOCLAB`) + Wazuh 4.14.5 SIEM (`192.168.100.50`).
- **Telemetry Verified:** Captured routine diagnostic handles from `VBoxService.exe` (`0x1400`), `svchost.exe` (`0x1000`), and `Taskmgr.exe` (`0x1400`).

![Rule 100103 Document Details](../01-Core-Detection-Labs/02-Kerberos-Attacks-and-Defense-Labs/15-LSASS-Ticket-Stealing-and-Memory-Dumping/images/07_wazuh_taskmgr_document_details_level12.jpg)

## Find it in Wazuh

```
rule.id: 100103
```
