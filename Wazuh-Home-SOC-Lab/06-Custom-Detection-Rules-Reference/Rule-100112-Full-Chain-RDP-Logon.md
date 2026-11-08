# Rule 100112 — Full Chain: New Privileged Account Logged On via RDP

*Part of [Custom Detection Rules — Master Reference](README.md). Status: **UNTESTED — and its parent chain is broken (see below). Do not test as written and expect it to fire.***

| Field | Value |
|---|---|
| Rule ID | 100112 |
| Level | 14 |
| Events | 4728 (privileged-group add) → 4624 type 10 (RDP logon), same user, within 1 hour |
| MITRE | **T1078** — Valid Accounts |
| Group | `privilege_escalation` |
| Source | Lab 03 |

## Rule

```xml
<rule id="100112" level="14" frequency="1" timeframe="3600">
  <if_sid>92653</if_sid>
  <if_matched_sid>100111</if_matched_sid>
  <same_user />
  <description>New privileged account logged on via RDP within 1 hour of the group add (full account-lifecycle chain)</description>
  <mitre>
    <id>T1078</id>
  </mitre>
  <group>privilege_escalation,</group>
</rule>
```

## What it detects

The **full account-lifecycle chain in one alert**: a new account, added to a privileged group, then logging on via RDP — all within one hour. Creation (4720) → privilege (4728) → logon (4624 type 10). One alert for the whole attack story, at level 14 — the highest level in this ruleset, because a fresh privileged account already logging in remotely is the compromise, not a warning sign.

## Purpose

Rules 100109, 100105, and 100111 each catch one link of the chain. This rule catches the chain itself: it fires only when the new privileged account actually **uses** its access. That is the moment the backdoor stops being a dormant account and becomes an active intrusion.

## How it works

- **`frequency="1" timeframe="3600"`** — fires once when its conditions are met within a **3600-second (1-hour)** window.
- **`<if_sid>92653</if_sid>`** — the parent is the built-in RDP logon rule 92653 (4624, logon type 10). The event must first have fired 92653.
- **`<if_matched_sid>100111</if_matched_sid>`** — the same chain must also have matched 100111 (new account → privileged group within 1 hour) within the window. This is the "new privileged account" half of the pattern.
- **`<same_user />`** — the group add and the logon must be for the **same user**.
- **Level 14** — the highest level in the ruleset, expressing that the full chain firing means the attack is complete and active.

## Shadowing and dependencies — READ THIS FIRST

- **BROKEN: the parent 92653 no longer fires.** This rule chains on `<if_sid>92653</if_sid>`, but 92653 is **shadowed by 100113/100114** (Lab 04, Nov 8–9, 2026): after the custom logon rules loaded, every RDP logon fired 100113/100114 and 92653 went silent (last firing Nov 8 18:08). A child rule can only fire when its parent fires — so **100112, as written, can never trigger**. The RDP link of the chain is dead.
- **The fix (redesign before testing):** re-parent 100112 on a rule that actually fires for a type-10 logon — either **100113** (if the chain account is the Administrator) or **100114** (for any normal user), or both. The redesign must be decided and the rule rewritten before the Lab 03 test; testing the current version and recording "it did not fire" would prove nothing except that the parent is shadowed, which is already known.
- **Scope limit (by design):** the rule only covers **RDP (type 10)** logons, because its parent is the RDP-specific 92653. A console (type 2) or network (type 3) logon by the new privileged account will not trigger it. That was a known scope limit when the rule was written; the redesign above should decide whether to keep it or broaden it.
- **Same `same_user` open question as 100111** — if Wazuh's `user` field does not align across the 4720/4728/4624 events, the correlation can never fire. Check the `user` field on the three alerts for the test account before concluding anything from a silent test.
- **Does not shadow anything itself.**

## Test evidence / test plan

**UNTESTED** — this rule has not been run in the lab, and it must not be tested as written (see the broken-parent note above).

1. **First, redesign:** change `<if_sid>92653</if_sid>` to the rule that actually fires for the chain account's RDP logon (100113 or 100114), update this file and the Lab 03 README with the new parent, and restart the manager.
2. **Then, positive chain:** create a fresh account (`svc-chain03` suggested), add it to `Domain-Admins-Custom`, then RDP in as that account within the hour → **100112 fires at level 14**. Record the 4720, the 4728, the 4624 type 10, and the 100112 alert with timestamps.
3. **Negative — old account:** an existing privileged account logging on via RDP → **100113/100114 fire only**, 100112 stays silent (no recent 100111 to match).
4. **Negative — logon without group add:** a fresh account logging on via RDP without any group add → **100114 fires only**, 100112 stays silent.

## Find it in Wazuh

```
rule.id: 100112
```

**One account, the whole chain:**
```
rule.id: 100112 OR rule.id: 100111 OR rule.id: 100105
```

## MITRE ATT&CK

**T1078 — Valid Accounts.** The final step of the chain: the attacker logs on with the valid credentials of the account they just created and escalated. The logon is the moment the backdoor becomes an intrusion — everything before it was preparation.
