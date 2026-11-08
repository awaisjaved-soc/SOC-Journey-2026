# Rule 100109 — Account Created Outside Business Hours

*Part of [Custom Detection Rules — Master Reference](README.md). Status: **TESTED** (Oct 17, 2026).*

| Field | Value |
|---|---|
| Rule ID | 100109 |
| Level | 10 |
| Event | 4720 (user account created) |
| MITRE | **T1136** — Create Account |
| Group | `privilege_escalation` |
| Source | Lab 02 |

## Rule

```xml
<rule id="100109" level="10">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4720$</field>
  <time>5 pm - 8 am</time>
  <description>Account created outside business hours (possible backdoor)</description>
  <mitre>
    <id>T1136</id>
  </mitre>
  <group>privilege_escalation,</group>
</rule>
```

## What it detects

A user account created **outside business hours** — event 4720 between 5 PM and 8 AM. HR creates accounts during the day; an account created at 3 AM is a potential backdoor.

## Purpose

The built-in rule 60109 fires at level 8 on every account creation, so a backdoor account created at night looks identical to a daytime onboarding. This rule adds the time dimension: the same event, at the wrong hour, fires louder (level 10). It was the first off-hours rule in the lab, and the pattern was reused for 100115 and 100116.

## How it works

- **`<if_group>windows</if_group>`** — only events decoded by the Windows decoder are evaluated.
- **`<field name="win.system.eventID">^4720$</field>`** — the event must be an account creation (4720).
- **`<time>5 pm - 8 am</time>`** — the event must occur between 5 PM and 8 AM, evaluated against the **manager's clock (UTC)**. In PKT that is 10 PM – 1 PM. A 4720 at noon does not match; a 4720 at 3 AM does. This is the same window used by 100115 and 100116.
- **Level 10** — above the built-in's level 8, expressing that the timing, not the creation itself, is the suspicious part.

## Shadowing and dependencies

- **No parent, no shadowing.** Independent rule. It fires *in addition* to 60109 — the built-in still fires on the same 4720 (level 8), and this rule adds the level-10 alert. Both alerts appear for an off-hours creation; that is expected, not a duplicate to suppress.
- **The time lesson (Oct 17, 2026):** the rule fired on its first test at 01:37 PKT — which is 20:37 UTC, inside the 5 PM – 8 AM window. An earlier daytime-based prediction that it "would not fire" was wrong, because the window is UTC, not local time. Always convert before concluding a time rule should or should not have fired.

## Test evidence

**TESTED Oct 17, 2026** (Lab 02):

- **Positive:** created a user at night → **100109 fired at level 10** (MITRE T1136), Oct 17 23:28 PKT. First custom rule written in the lab that fired on the first try.
- **Negative:** an account created during business hours → no 100109 alert (60109 fires alone at level 8).
- **Chain-lab re-confirmation (Nov 3, 2026):** the fresh 4720 for `svc-backup` fired 100109 at L10 (01:37:13) — the off-hours window held.

## Find it in Wazuh

```
rule.id: 100109
```

## MITRE ATT&CK

**T1136 — Create Account.** Adversaries create new accounts to maintain access — a backdoor account that persists after the initial compromise is closed. An account created outside business hours is the classic form: nobody in HR is onboarding at 3 AM.
