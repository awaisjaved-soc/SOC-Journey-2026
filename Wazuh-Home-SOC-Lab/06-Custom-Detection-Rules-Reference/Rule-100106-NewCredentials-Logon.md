# Rule 100106 — NewCredentials Logon (Type 9)

*Part of [Custom Detection Rules — Master Reference](README.md). Status: **UNTESTED**.*

| Field | Value |
|---|---|
| Rule ID | 100106 |
| Level | 10 |
| Event | 4624 (successful logon), logon type 9 (NewCredentials) |
| MITRE | **T1550.002** — Use Alternate Authentication Material: Pass the Hash |
| Group | `lateral_movement` |
| Source | Rule pack (`local_rules.xml`, 100100–100108) |

## Rule

```xml
<rule id="100106" level="10">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4624$</field>
  <field name="win.eventdata.logonType">^9$</field>
  <description>NewCredentials logon (type 9, e.g. RunAs) — possible credential reuse / pass-the-hash</description>
  <mitre>
    <id>T1550.002</id>
  </mitre>
  <group>lateral_movement,</group>
</rule>
```

## What it detects

A logon with **explicit credentials** — logon type 9 (NewCredentials). This is what happens with RunAs: a user already logged on authenticates a second time with a different set of credentials, and the new identity is used for network access while the original session continues.

## Purpose

Type 9 is the legitimate admin pattern (RunAs as Administrator) and the attacker pattern (reuse a stolen hash or a second account without logging off) at the same time. A type-9 logon is worth a level-10 alert because it means someone is operating under a second identity — and the second identity is usually the privileged one.

## How it works

- **`<if_group>windows</if_group>`** — only events decoded by the Windows decoder are evaluated.
- **`<field name="win.system.eventID">^4624$</field>`** — the event must be a successful logon (4624).
- **`<field name="win.eventdata.logonType">^9$</field>`** — the logon type must be exactly **9** (NewCredentials). Types 2, 3, and 10 do not match — those are covered by 100113/100114/100115 instead.
- **Level 10** — high, because a second identity in use is the step where privilege escalation becomes lateral movement.

## Shadowing and dependencies

- **No parent, no shadowing.** Independent rule.
- **Overlap note:** 100113/100114 cover logon types 2, 3, and 10 only — type 9 is outside their scope, so there is no conflict and no double-firing between this rule and the Lab 04 pair. A type-9 logon fires 100106; a type-2/3/10 logon fires 100113 or 100114.
- **Related event:** 4648 (logon with explicit credentials) is the companion event to a type-9 4624 — it fires when the explicit credentials are used. The 4648 row in the Phase 2 sheet is still "verify in lab".

## Test evidence / test plan

**UNTESTED** — this rule has not been run in the lab. Test plan:

1. Positive: on the DC, run `runas /user:SOCLAB\administrator "cmd.exe"` and authenticate → a type-9 4624 should fire rule 100106 at level 10. Record the target user, the subject user, and the logon type from the alert.
2. Negative: a normal RDP logon (type 10) → no 100106 alert (100113/100114 fire instead).
3. Record whether the alert distinguishes the RunAs case from a pass-the-hash case — the rule cannot tell them apart by itself; the triage is the subject account and the process that requested the logon.

## Find it in Wazuh

```
rule.id: 100106
```

## MITRE ATT&CK

**T1550.002 — Use Alternate Authentication Material: Pass the Hash.** Adversaries use stolen hashes (or a second set of credentials) to authenticate without the plaintext password. A NewCredentials logon is the visible form of that reuse: the attacker never types a password, they present material they already hold.
