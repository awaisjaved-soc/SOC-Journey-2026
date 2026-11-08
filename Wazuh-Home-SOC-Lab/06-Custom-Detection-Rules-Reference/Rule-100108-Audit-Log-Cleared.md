# Rule 100108 — Audit Log Cleared (Event 1102)

*Part of [Custom Detection Rules — Master Reference](README.md). Status: **TESTED** (Nov 5, 2026 — chain lab, step 5).*

| Field | Value |
|---|---|
| Rule ID | 100108 |
| Level | 12 |
| Event | 1102 (audit log was cleared) |
| MITRE | **T1070.001** — Indicator Removal: Clear Windows Event Logs |
| Group | `defense_evasion` |
| Source | Rule pack (`local_rules.xml`, 100100–100108); chain lab step 5 |

## Rule

```xml
<rule id="100108" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^1102$</field>
  <description>Windows audit log was cleared (possible defense evasion, event 1102)</description>
  <mitre>
    <id>T1070.001</id>
  </mitre>
  <group>defense_evasion,</group>
</rule>
```

## What it detects

The Windows Security audit log being cleared (event 1102). Clearing the log is the attacker's cleanup step: after doing the damage, erase the record so the SOC cannot see what happened.

## Purpose

Event 1102 is rare in normal operation — administrators almost never clear the Security log on a domain controller. When it fires, it almost always means someone is hiding something, and it is usually the last step of an attack chain. Level 12 expresses that this is a defense-evasion event, not a routine admin action.

## How it works

- **`<if_group>windows</if_group>`** — only events decoded by the Windows decoder are evaluated.
- **`<field name="win.system.eventID">^1102$</field>`** — the event must be exactly 1102 (audit log cleared). No other condition: any clear, by any account, matches.
- **Level 12** — high, because log clearing is the indicator that the attacker knows they are being watched and is actively destroying evidence.

## Shadowing and dependencies

- **No parent, no shadowing.** Independent rule.
- **The irony of this rule:** clearing the log empties the DC's local Security log, but Wazuh has already received and stored the events — the 1102 itself is forwarded to Wazuh before the log is gone. The attacker destroys the local copy; the SIEM keeps the evidence. That is the point of forwarding logs off the host.

## Test evidence

**TESTED Nov 5, 2026** (chained attack lab, step 5):

- **Positive:** `Clear-EventLog -LogName Security` run from the **admin** session on the DC → **100108 fired at level 12**, Nov 5 15:38:54, eventRecordID 27176. (The svc-chain02 session could not clear the log — its token is UAC-filtered, so Access Denied was expected there; the admin session was required.)
- The alert was screenshot-verified (Admin PowerShell generation shot, 100108 alert list, detail, rule/MITRE detail) in the chain-lab folder.
- **Negative (by design):** no other lab action generates 1102 — the rule only fires on an actual log clear, so there is no routine false positive to record.

## Find it in Wazuh

```
rule.id: 100108
```

## MITRE ATT&CK

**T1070.001 — Indicator Removal: Clear Windows Event Logs.** Adversaries clear Windows event logs to hide their activity and erase evidence of the intrusion. It is typically the last step of an attack — which is why it is also the most urgent: if the logs are being cleared, the attack has already happened, and the SIEM's forwarded copy is now the only record.
