# Rule 100110 — Built-in Administrator Account Modified

*Part of [Custom Detection Rules — Master Reference](README.md). Status: **TESTED** (Oct 18, 2026).*

| Field | Value |
|---|---|
| Rule ID | 100110 |
| Level | 10 |
| Event | 4738 (user account changed), target SID ending -500 |
| MITRE | **T1098** — Account Manipulation |
| Group | `privilege_escalation` |
| Source | Lab 02 |

## Rule

```xml
<rule id="100110" level="10">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4738$</field>
  <field name="win.eventdata.targetSid">-500$</field>
  <description>Built-in Administrator account (RID 500) modified (possible persistence)</description>
  <mitre>
    <id>T1098</id>
  </mitre>
  <group>privilege_escalation,</group>
</rule>
```

## What it detects

Any modification to the **built-in Administrator account** — display name, enable/disable, description, profile attributes (event 4738, target SID ending in `-500`). The most powerful account in the domain being edited is a persistence move: an attacker who can modify the Administrator can keep it, hide it, or re-enable it.

## Purpose

The built-in rule 60110 fires at level 8 on *any* account change, even an address edit. This rule narrows to the one account whose modification matters most, and fires louder (level 10). It is also the rule that taught the lab's most important lesson: **names are fragile, SIDs are stone.**

## How it works

- **`<if_group>windows</if_group>`** — only events decoded by the Windows decoder are evaluated.
- **`<field name="win.system.eventID">^4738$</field>`** — the event must be a user-account change (4738).
- **`<field name="win.eventdata.targetSid">-500$</field>`** — the changed account's SID must end in **`-500`**, the well-known RID of the built-in Administrator. The SID never changes when the account is renamed — that is the whole point.
- **Level 10** — above the built-in's level 8, expressing that the target (the Administrator), not the change itself, is what matters.

## Shadowing and dependencies

- **No parent, no shadowing.** Independent rule.
- **The rename discovery (Lab 02's best finding):** the first version of this rule matched `targetUserName` against group names — it never fired, because 4738's target is always a **user**, never a group. The second version matched `^Administrator$` — and then suddenly stopped firing, because the Administrator account had been renamed to `Administratorss` during testing. The rule went blind on a rename: **an accidental self-evasion, exactly what a real attacker does.** Switching to the `-500` SID made it rename-proof. Any detection based on account names can be evaded with a rename; this rule is the proof.
- **4738 fidelity note:** the event only reports attributes in its tracked list (Display Name, SAM account name, UPN, Script Path, Profile Path, UAC). Changes to `givenName` or `sn` fire the event but leave all Changed Attributes blank (`-`). The rule fires on the change; the alert may not say *what* changed.

## Test evidence

**TESTED Oct 18, 2026** (Lab 02):

- **Positive:** modified the Administrator account (display name, profile attributes) → **100110 fired at level 10** after the SID fix.
- **Negative:** modified a normal user account → no 100110 alert (60110 fires alone at level 8).
- **Boundary test:** every attribute on the Administrator account was changed systematically to map what generates a 4738 — Display Name, UAC enable/disable, description, Script Path, Profile Path, and UPN all generate 4738s the rule catches. `givenName`/`sn` changes fire the event with blank details (the fidelity gap above).
- **The two bugs, fixed in the lab:** v1 matched group names against a user-targeted event (never fired); v2 matched `^Administrator$` and went blind on the rename to `Administratorss`. The final SID-based version is what is documented here.

## Find it in Wazuh

```
rule.id: 100110
```

## MITRE ATT&CK

**T1098 — Account Manipulation.** Adversaries modify accounts to maintain access — re-enabling a disabled Administrator, changing its description to hide it, or editing its profile to blend in. The modification itself is the persistence step.
