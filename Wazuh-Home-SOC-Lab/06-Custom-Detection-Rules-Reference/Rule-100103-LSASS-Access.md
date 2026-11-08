# Rule 100103 — Possible Credential Dumping (Process Opened LSASS)

*Part of [Custom Detection Rules — Master Reference](README.md). Status: **UNTESTED**.*

| Field | Value |
|---|---|
| Rule ID | 100103 |
| Level | 12 |
| Event | Sysmon event 10 (ProcessAccess), target image `lsass.exe` |
| MITRE | **T1003.001** — OS Credential Dumping: LSASS Memory |
| Group | `credential_access` |
| Source | Rule pack (`local_rules.xml`, 100100–100108) |

## Rule

```xml
<rule id="100103" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^10$</field>
  <field name="win.eventdata.targetImage">lsass.exe</field>
  <description>Possible credential dumping: process opened LSASS (Sysmon event 10)</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
  <group>credential_access,</group>
</rule>
```

## What it detects

A process opening **LSASS** (Local Security Authority Subsystem Service) — the process that holds credentials in memory. Sysmon event 10 (ProcessAccess) records it. This is the Mimikatz pattern: read LSASS memory, extract passwords and hashes.

## Purpose

LSASS holds the keys to the domain: every password and hash that has been used on the machine passes through it. There is almost no legitimate reason for a normal process to open LSASS memory — the processes that do it are credential-dumping tools. Level 12 expresses that this is an active credential-theft attempt, not a suspicious logon.

## How it works

- **`<if_group>windows</if_group>`** — only events decoded by the Windows decoder are evaluated.
- **`<field name="win.system.eventID">^10$</field>`** — the event must be Sysmon event **10** (ProcessAccess). This is a Sysmon event ID, not a Windows Security event ID — it arrives on the `Microsoft-Windows-Sysmon/Operational` channel, which was verified flowing to Wazuh on Nov 5, 2026.
- **`<field name="win.eventdata.targetImage">lsass.exe</field>`** — the process being accessed must be `lsass.exe`. Any other target image does not match. (Note: the match is a substring/regex on the field — `lsass.exe` matches the full path ending in `lsass.exe`.)
- **Level 12** — high, because LSASS access is the step immediately before credential theft.

## Shadowing and dependencies

- **No parent, no shadowing.** Independent rule; it does not suppress any built-in rule.
- **Depends on Sysmon being installed and its ProcessAccess events flowing.** Sysmon event 10 is only generated if Sysmon is running with a configuration that logs ProcessAccess — the default Sysmon configuration does not log every process access, and an overly broad one floods. Verify that Sysmon 10 events for `lsass.exe` actually reach Wazuh before trusting this rule.
- **Known tuning risk:** legitimate security tools (antivirus, EDR) also open LSASS. If this rule fires on your own AV, the fix is an exclusion for that process's image path — not disabling the rule. Record any such exclusion here when found.

## Test evidence / test plan

**UNTESTED** — this rule has not been run in the lab. Test plan:

1. Verify Sysmon event 10 is flowing: in Threat Hunting, search `data.win.system.eventID: 10` and confirm Sysmon ProcessAccess events appear.
2. Positive: in the isolated lab VM only, run a process that opens LSASS memory (e.g. a test credential-dump against your own lab account — never against a real person's machine) → rule 100103 fires at level 12. Record the source image, the target image, and the granted access.
3. Negative: normal activity (opening a browser, running PowerShell) → no 100103 alert.
4. Record any legitimate process that triggers it (AV, EDR) and note the exclusion needed.

## Find it in Wazuh

```
rule.id: 100103
```

## MITRE ATT&CK

**T1003.001 — OS Credential Dumping: LSASS Memory.** Adversaries access LSASS process memory to extract credentials — passwords, hashes, and Kerberos tickets. This is the technique behind Mimikatz and most Windows credential theft: one LSASS read can yield every credential used on the machine.
