# Rule 100107 — Network Logon to a High-Value Account

*Part of [Custom Detection Rules — Master Reference](README.md). Status: **UNTESTED**.*

| Field | Value |
|---|---|
| Rule ID | 100107 |
| Level | 8 |
| Event | 4624 (successful logon), logon type 3 (network), target Administrator or krbtgt |
| MITRE | **T1021.002** — Remote Services: SMB/Windows Admin Shares |
| Group | `lateral_movement` |
| Source | Rule pack (`local_rules.xml`, 100100–100108) |

## Rule

```xml
<rule id="100107" level="8">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4624$</field>
  <field name="win.eventdata.logonType">^3$</field>
  <field name="win.eventdata.targetUserName">^Administrator$|^krbtgt$</field>
  <description>Network logon to a high-value account (possible lateral movement via SMB)</description>
  <mitre>
    <id>T1021.002</id>
  </mitre>
  <group>lateral_movement,</group>
</rule>
```

## What it detects

A **network logon (type 3)** to one of the two highest-value accounts in the domain: `Administrator` or `krbtgt` (the Kerberos ticket-granting-ticket account). A network logon carries the full token (unlike an interactive logon, which gets a UAC-filtered token), so this is the lateral-movement pattern: someone authenticating over the network as the most powerful account, from somewhere else.

## Purpose

The built-in 60106 fires on every 4624 and says nothing about which account. This rule isolates the one combination that matters most for lateral movement — the most powerful accounts, over the network, where their privileges work at full strength. Level 8 expresses that this is suspicious but not yet confirmed malicious: an admin mapping a drive is also a type-3 logon to Administrator.

## How it works

- **`<if_group>windows</if_group>`** — only events decoded by the Windows decoder are evaluated.
- **`<field name="win.system.eventID">^4624$</field>`** — the event must be a successful logon (4624).
- **`<field name="win.eventdata.logonType">^3$</field>`** — the logon type must be exactly **3** (network). Console (2) and RDP (10) do not match.
- **`<field name="win.eventdata.targetUserName">^Administrator$|^krbtgt$</field>`** — the target account must be exactly `Administrator` or exactly `krbtgt`. The `^...$` anchors mean an exact match — `Administrator2` or `krbtgt-backup` would not match. (Known limitation, same as the Lab 02 lesson: this matches on **name**, not SID. If the Administrator account is renamed, this rule goes blind. The SID-based version is the follow-up — match `targetUserSid` ending `-500` for Administrator, and the krbtgt well-known SID for krbtgt.)
- **Level 8** — above the built-in's level 3, below a confirmed compromise, because a network logon to Administrator can be legitimate admin work.

## Shadowing and dependencies

- **No parent, no shadowing.** Independent rule.
- **Overlap note:** a type-3 logon as Administrator also fires **100113** (level 10, SID-based) — the two rules will fire on the same event, and that is expected: 100113 says "the Administrator logged on", 100107 says "and it was over the network to a high-value account". Two alerts, two angles on the same logon.
- **Name-matching limitation:** see above — the `^Administrator$` match is rename-fragile. 100113 already does this correctly by SID; this rule should be aligned to the same pattern.

## Test evidence / test plan

**UNTESTED** — this rule has not been run in the lab. Test plan:

1. Positive: from your PC, map a drive to the DC as Administrator (`net use \\192.168.100.146\C$ /user:SOCLAB\administrator`) → rule 100107 fires at level 8, and 100113 also fires at level 10 (both on the same type-3 logon — record both).
2. Negative: a network logon as a normal user (`svc-chain02` mapping the same share) → no 100107 alert (100114 fires instead).
3. Negative (rename): rename the Administrator account, repeat the positive test → if 100107 goes silent while 100113 still fires, the name-matching limitation is confirmed, and the rule should be rewritten to match on SID.

## Find it in Wazuh

```
rule.id: 100107
```

## MITRE ATT&CK

**T1021.002 — Remote Services: SMB/Windows Admin Shares.** Adversaries use SMB and the Windows admin shares (C$, ADMIN$) to move laterally between machines, authenticating as a privileged account over the network. A type-3 logon to Administrator from an unusual source is that movement happening.
