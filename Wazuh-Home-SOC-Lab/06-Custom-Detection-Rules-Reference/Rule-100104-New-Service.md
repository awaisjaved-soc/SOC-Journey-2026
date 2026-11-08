# Rule 100104 — New Service Installed (Possible Persistence)

*Part of [Custom Detection Rules — Master Reference](README.md). Status: **UNTESTED**.*

| Field | Value |
|---|---|
| Rule ID | 100104 |
| Level | 8 |
| Event | 7045 (a service was installed in the system) |
| MITRE | **T1543.003** — Create or Modify System Process: Windows Service |
| Group | `persistence` |
| Source | Rule pack (`local_rules.xml`, 100100–100108) |

## Rule

```xml
<rule id="100104" level="8">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^7045$</field>
  <description>A new service was installed (possible persistence mechanism, event 7045)</description>
  <mitre>
    <id>T1543.003</id>
  </mitre>
  <group>persistence,</group>
</rule>
```

## What it detects

A new Windows service being installed (event 7045). Services run at boot with SYSTEM privileges and survive logoffs — installing one is the classic way to make malware persist across reboots.

## Purpose

Attackers who gain a foothold need to survive a reboot, and a new service is one of the quietest ways to do it: it looks like legitimate software installation, it runs automatically, and it runs as SYSTEM. Level 8 expresses that a new service is worth investigating, without claiming every install is malicious — software installs do this too.

## How it works

- **`<if_group>windows</if_group>`** — only events decoded by the Windows decoder are evaluated.
- **`<field name="win.system.eventID">^7045$</field>`** — the event must be 7045 (a service was installed in the system). No other condition: any service install, by any account, from any path, matches.
- **Level 8** — moderate-high. A new service is not proof of compromise (legitimate installers do it), but it is the persistence mechanism to check first, so it sits above routine noise and below confirmed credential theft.

## Shadowing and dependencies

- **No parent, no shadowing.** Independent rule; it does not suppress any built-in rule.
- **Tuning risk (known):** legitimate software installation also generates 7045, so this rule will fire on every install. The triage is the service name and binary path on the alert — an unknown service with a binary in `Temp`, `AppData`, or `ProgramData` is the suspicious pattern; a named product install is not. A future refinement could exclude known installer paths, but that is not built here.

## Test evidence / test plan

**UNTESTED** — this rule has not been run in the lab. Test plan:

1. Positive: install a service in the lab (e.g. `sc.exe create TestSvc binPath= "C:\Windows\System32\notepad.exe"`) → rule 100104 fires at level 8. Record the service name and binary path from the alert. Then remove it (`sc.exe delete TestSvc`).
2. Negative: starting/stopping an existing service → no 100104 alert (7045 is install-only, not start/stop).
3. Record whether the alert carries the service name and binary path — those two fields are what the triage depends on.

## Find it in Wazuh

```
rule.id: 100104
```

## MITRE ATT&CK

**T1543.003 — Create or Modify System Process: Windows Service.** Adversaries create or modify Windows services to execute malicious code at startup with elevated privileges. A new service is persistence: it survives reboots and logoffs, and it runs as SYSTEM by default.
