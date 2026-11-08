# Rule 100111 — New Account Added to a Privileged Group Within 1 Hour

*Part of [Custom Detection Rules — Master Reference](README.md). Status: **UNTESTED**.*

| Field | Value |
|---|---|
| Rule ID | 100111 |
| Level | 12 |
| Events | 4720 (creation) → 4728 (privileged-group add), same user, within 1 hour |
| MITRE | **T1098** — Account Manipulation |
| Group | `privilege_escalation` |
| Source | Lab 03 |

## Rule

```xml
<rule id="100111" level="12" frequency="1" timeframe="3600">
  <if_sid>100105</if_sid>
  <if_matched_sid>60109</if_matched_sid>
  <same_user />
  <description>New account added to a privileged group within 1 hour of creation</description>
  <mitre>
    <id>T1098</id>
  </mitre>
  <group>privilege_escalation,</group>
</rule>
```

## What it detects

A **new account added to a privileged group within one hour of being created**. One alert for the whole pattern: the account did not exist an hour ago, and it is already a privileged-group member. That is the backdoor-account pattern — create, escalate, use — compressed into a single alert instead of two separate ones an analyst must connect by hand.

## Purpose

Rules 100109 (creation) and 100105 (privileged-group add) each fire on their own half of the pattern. An analyst triaging them separately must notice that the same account appears in both, an hour apart. This rule does that correlation in the engine: it fires only when both halves happen for the same account inside one hour, at level 12 — louder than either parent, because the *combination* is the attack.

## How it works

- **`frequency="1" timeframe="3600"`** — the rule fires once when its conditions are met within a **3600-second (1-hour)** window.
- **`<if_sid>100105</if_sid>`** — the parent is the custom privileged-group rule 100105. The event must first have fired 100105 (a 4728 to a privileged group). This is the deliberate choice: the parent is 100105, **not** 60141, because 60141 is shadowed on privileged 4728s and never fires there — a rule chained on 60141 would go blind.
- **`<if_matched_sid>60109</if_matched_sid>`** — the same event chain must also have matched 60109 (the built-in account-creation rule, event 4720) within the window. This is the "new account" half of the pattern.
- **`<same_user />`** — the 4720 and the 4728 must be for the **same user**. Without this, any creation plus any privileged-group add within the hour would fire the rule, even for different accounts.
- **Level 12** — above both parents (100105 at 10, 60109 at 8), expressing that the correlated pattern is more serious than either event alone.

## Shadowing and dependencies

- **Depends on 100105.** If 100105 is ever removed, this rule dies with it — its parent is a custom rule, not a built-in.
- **Depends on 60109 firing on the creation.** 60109 is a built-in rule and is not shadowed, so this half is safe.
- **Open question — `same_user` alignment.** This is the rule's honest uncertainty: if Wazuh's `user` field on the 4720/4728 is the **subject** (the administrator who performed the action) while on the 4624 it is the **target** (the new account), the correlation can never align. The test must check this first — add `user` as a Discover column and compare the value across the 60109, 100105, and 4624 alerts for the test account. If they do not align, the fallback is to drop `<same_user />` or rescope the rule.
- **Does not shadow anything itself.** It fires in addition to its parents' alerts.

## Test evidence / test plan

**UNTESTED** — this rule has not been run in the lab. Test plan (from Lab 03, full version in the Lab 03 README):

1. **Positive chain:** create a fresh account (`svc-chain03` suggested), then within the hour add it to `Domain-Admins-Custom` → **100111 fires at level 12**. Record the 4720, the 4728, and the 100111 alert with timestamps.
2. **Negative — old account:** add an existing account (created days ago) to the privileged group → **100105 fires only**, 100111 stays silent (no recent 60109 to match).
3. **Negative — normal group:** create a fresh account and add it to a normal group (`GG-Sales`) → **60141 fires only**, 100111 stays silent (no 100105 parent).
4. **Negative — logon without group add:** create a fresh account and log it on without any group add → neither 100111 nor 100112 fires.
5. **First check the `same_user` question** (above) before concluding a silent test means the rule is broken — a misaligned `user` field looks identical to a rule that never matched.

## Find it in Wazuh

```
rule.id: 100111
```

**One account, the whole chain:**
```
rule.id: 100111 OR rule.id: 100105 OR rule.id: 60109
```

## MITRE ATT&CK

**T1098 — Account Manipulation.** Creating an account and immediately adding it to a privileged group is the backdoor-account pattern: the attacker creates the identity and escalates it in one motion, so that by the time anyone notices the account, it already has the keys.
