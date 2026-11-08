# Rule 100101 — Possible RDP Brute Force (8 Failed Type-10 Logons in 120 Seconds)

*Part of [Custom Detection Rules — Master Reference](README.md). Status: **UNTESTED**.*

| Field | Value |
|---|---|
| Rule ID | 100101 |
| Level | 10 |
| Event | 4625 (failed logon), logon type 10 (RDP), via parent rule 60122 |
| MITRE | **T1110** — Brute Force |
| Group | `authentication_failures` |
| Source | Rule pack (`local_rules.xml`, 100100–100108) |

## Rule

```xml
<rule id="100101" level="10" frequency="8" timeframe="120">
  <if_matched_sid>60122</if_matched_sid>
  <field name="win.eventdata.logonType">^10$</field>
  <description>Possible RDP brute force: 8 failed logons (type 10) within 120 seconds</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>authentication_failures,</group>
</rule>
```

## What it detects

Eight failed **RDP** logons within 120 seconds. The same brute-force pattern as 100100, narrowed to Remote Desktop — the service attackers actually target from outside.

## Purpose

RDP is the most common remote entry point in the lab's threat model: it is exposed, it accepts password authentication, and a successful guess hands the attacker a full desktop. A brute-force burst specifically against RDP deserves its own alert, distinct from generic failed logons (which include console typos and service-account noise).

## How it works

- **`frequency="8" timeframe="120"`** — fires when the parent has matched 8 times within 120 seconds.
- **`<if_matched_sid>60122</if_matched_sid>`** — counts the built-in failed-logon rule's hits, same as 100100.
- **`<field name="win.eventdata.logonType">^10$</field>`** — the narrowing condition: only logon type **10** (RemoteInteractive — RDP) counts. A failed console logon (type 2) or network logon (type 3) does not increment this rule's counter.
- **Level 10** — same as 100100, expressing that an RDP-targeted burst is as serious as a generic burst.

## Shadowing and dependencies

- **Depends on 60122** — same dependency as 100100, with the same off-hours caveat: rule 100116 suppresses 60122 during off-hours, which may starve this rule's counter at night.
- **A failed RDP logon is always type 3, never type 10.** This is the critical flaw to understand before testing. A type 10 means an RDP **session was created**; a failed authentication never creates a session, so Windows records the 4625 as a network (type 3) failure. **This rule, as written, can likely never fire** — it waits for 8 failed logons of type 10, and failed RDP logons do not carry type 10. This was proven in the lab on Nov 9, 2026 (every failed RDP attempt recorded logonType 3). The rule needs a redesign: count failed logons **from the RDP source IP** (192.168.100.27) or count 4625s that follow an RDP connection attempt, rather than filtering on logonType 10. Until then, treat this rule as a documented design error, not a working detection.
- **Does not shadow anything itself.**

## Test evidence / test plan

**UNTESTED** — this rule has not been run in the lab, and the test is expected to demonstrate the design flaw above rather than a firing alert:

1. From your PC, attempt 8 RDP logons with a wrong password against a throwaway test account within 2 minutes (mind the 5-attempt lockout threshold — use a dedicated account and unlock it afterwards).
2. Expected result: **no 100101 alert**, because every 4625 will carry logonType 3, not 10. Confirm by checking the `logonType` on the fired 60122/100116 alerts.
3. If that confirms the flaw, redesign the rule (count by source IP or by 4625s during an RDP session window) and record the new version here.

## Find it in Wazuh

```
rule.id: 100101
```

## MITRE ATT&CK

**T1110 — Brute Force.** Repeated guessing against RDP specifically — the technique behind most internet-facing Windows compromises. The rule's intent is correct; its logonType condition is not, and the fix is part of the test above.
