# Rule 100100 — Possible Brute Force (8 Failed Logons in 120 Seconds)

*Part of [Custom Detection Rules — Master Reference](README.md). Status: **UNTESTED**.*

| Field | Value |
|---|---|
| Rule ID | 100100 |
| Level | 10 |
| Event | 4625 (failed logon), via parent rule 60122 |
| MITRE | **T1110** — Brute Force |
| Group | `authentication_failures` |
| Source | Rule pack (`local_rules.xml`, 100100–100108) |

## Rule

```xml
<rule id="100100" level="10" frequency="8" timeframe="120">
  <if_matched_sid>60122</if_matched_sid>
  <description>Possible brute force attack: 8 failed logons within 120 seconds</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>authentication_failures,</group>
</rule>
```

## What it detects

Eight failed logons (event 4625) within 120 seconds. One failed logon is a typo; eight in two minutes is someone guessing passwords.

## Purpose

The built-in rule 60122 fires at level 5 on **every** failed logon, so a brute-force burst looks identical to a single typo. This rule counts the failures and fires louder (level 10) only when the count crosses a threshold inside a short window — the difference between a user mistyping and an attacker guessing.

## How it works

- **`frequency="8" timeframe="120"`** — the rule only fires when the parent rule has matched **8 times within 120 seconds**. These two attributes sit on the `<rule>` tag itself, not inside a field.
- **`<if_matched_sid>60122</if_matched_sid>`** — the parent is the built-in failed-logon rule 60122. Every time 60122 fires, it counts toward the 8. This is the frequency-rule pattern: the child counts the parent's hits.
- **No `<field>` conditions** — the rule does not filter by account, IP, or logon type. Any 8 failed logons in 120 seconds, against any account from any source, trigger it. That breadth is a known tuning gap (see below).
- **`<mitre><id>T1110</id></mitre>`** — MITRE T1110 (Brute Force). The `<mitre>` element takes `<id>` only — a `<tactic>` or `<technique>` element inside it will prevent the manager from starting.
- **Level 10** — double the parent's level 5, expressing that a *pattern* of failures is more serious than one failure.

## Shadowing and dependencies

- **Depends on 60122.** If 60122 stops firing, this rule can never count to 8. That matters since Nov 9, 2026: rule **100116** (off-hours failed logon) is also a child of 60122 and **suppresses 60122 during off-hours**. During off-hours, failed logons fire 100116, not 60122 — so this rule's counter may never reach 8 at night, because its parent is shadowed. The on-hours window is unaffected (100116 does not match then, so 60122 fires and the counter runs). This interaction was not considered when the rule was written and should be verified in testing.
- **Does not shadow anything itself.** It fires *in addition* to 60122's individual alerts (each failure still generates its own 60122 alert; the 8th also generates this one).

## Test evidence / test plan

**UNTESTED** — this rule has not been run in the lab. Test plan:

1. From your PC, attempt 8 RDP logons with a wrong password against `svc-chain02` within 2 minutes. **Warning:** the domain lockout policy locks an account after **5** invalid attempts in 30 minutes (threshold 5, duration 30 min, observation window 30 min) — the account will lock out before you reach 8. Use a dedicated throwaway test account for this test, and unlock it afterwards (`Unlock-ADAccount -Identity <user>`).
2. Positive: rule 100100 fires at level 10 after the 8th failure.
3. Negative: 7 failures in 120 seconds → no 100100 alert (60122 fires 7 times, the counter does not reach 8).
4. Record the `firedtimes` and whether the 8 individual 60122 alerts also appear (they should — this rule adds an alert, it does not replace them).
5. Open item: verify the off-hours interaction with 100116 — run the same test at night and check whether 100100 still fires, or whether 100116's suppression of 60122 starves the counter.

## Find it in Wazuh

```
rule.id: 100100
```

## MITRE ATT&CK

**T1110 — Brute Force.** Adversaries repeatedly attempt to guess credentials — passwords, PINs, or keys — against an authentication service. Eight failures in two minutes is the signature: no legitimate user mistypes eight times in a row that fast.
