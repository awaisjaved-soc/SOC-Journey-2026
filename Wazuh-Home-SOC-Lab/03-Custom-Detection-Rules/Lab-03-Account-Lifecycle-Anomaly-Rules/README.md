# Lab 03 — Account-Lifecycle Anomaly Rules (100111 & 100112)

*Part of [03-Custom-Detection-Rules](../README.md). The correlation idea: catch the whole chain — new account, privileged group, then logon — in one rule.*

---

> **Status: UNTESTED.** These rules are written from Wazuh's documented rule syntax. They have not been run in the lab yet. Do not treat them as verified detection until the chain test below has been executed and the alerts observed in Threat Hunting.

## The problem

The chained-attack lab ([Lab 05](../01-Core-Detection-Labs/05-Chained-Attack-One-Incident-Five-Alerts/)) produced five separate alerts: 4720 (60109), 4728 (100105), 4624 (92653), 4688 (67027), 1102 (100108). Each one is a single event. Nothing fires on the **sequence** — and the sequence is the attack. A brand-new account that is added to a privileged group and then logs on within the hour is a very different story from any one of those events alone. An analyst staring at a flood of 60106 logon rows will miss it. Lab 06 (the purple-team story) named this as the gap underneath all five steps. This lab closes it.

## The design

Two rules, chained. Each one waits for the previous link, then fires louder:

```
4720 (new account)  ──60109──▶  100111: 4728 to a privileged group
                                  within 1 hour of creation (level 12)
                                        │
                                        ▼
                                 100112: RDP logon (type 10)
                                  within 1 hour of the group add (level 14)
```

The mechanism is Wazuh's correlation trio, the same pattern the pack's brute-force rules (100100/100101) already use:

- `<if_sid>` — the current event must have matched this parent rule. For 100111 that is **100105** (the privileged-group rule); for 100112 it is **92653** (the RDP logon rule).
- `<if_matched_sid>` — the earlier rule must have matched at least `frequency` times within `timeframe`. For 100111 that is **60109** (account created); for 100112 it is **100111** itself.
- `<same_user />` — the account in both events must be the same. This is what stops the rule from firing when two unrelated accounts happen to do these things in the same hour.
- `frequency="1" timeframe="3600"` — one match of the earlier rule within one hour is enough. The chain lab's steps were 10–25 minutes apart, so one hour covers the lab chain with room to spare. Widen it if your attacker moves slower; narrow it if the false positives pile up.

### Why 100111 sits on 100105, not on 60141

This is the shadowing lesson from Lab 01, applied. On a privileged 4728, custom rule **100105 fires and built-in 60141 stays silent** — the custom rule shadows the built-in one on match. A correlation rule chained on 60141 would therefore **never fire for privileged groups**, because its parent never fires. 100111 chains on 100105 instead. The dependency cuts both ways: if 100105 is ever removed or disabled, 100111 goes blind with it. Know what your rules stand on.

## The rules

Copy-paste ready — the same XML also lives in [`local_rules-100111-100112.xml`](local_rules-100111-100112.xml) in this folder. Append both rules inside the `<group>` of `local_rules.xml` on the manager.

```xml
<!-- 100111: new account added to a privileged group within 1 hour -->
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

<!-- 100112: the full chain in ONE alert — new privileged account logged on -->
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

Levels are deliberate: 100111 at 12 because a fresh account reaching a privileged group is already high severity; 100112 at 14 because by then the attacker has an **interactive privileged session** — the chain is complete. MITRE: T1098 (Account Manipulation) for the group add, T1078 (Valid Accounts) for the logon. The RDP step also maps to T1021.001 (Remote Services: RDP); T1078 is the primary tag because the account is the story.

## Install

On the manager (Kali), from the folder holding your `local_rules.xml`:

```bash
docker cp local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

No `-it` — these are non-interactive commands. Then confirm the rules loaded before testing: on the manager, run the config test (`wazuh-analysisd -t` — it must report no errors) and check the manager log for the ruleset load. **Do not assert the rules loaded from the restart log alone** — the proof is the test below, where the alerts either appear or they don't.

## Test plan

Run the chain again with a **fresh account** (never reuse `svc-chain02` — the rules key on new accounts, and a reused account has no recent 4720). Suggested name: `svc-chain03`.

**Positive test — the full chain should produce both new alerts:**

| Step | Action | Expected alert |
|---|---|---|
| 1 | Create `svc-chain03` (`New-ADUser`) | 60109 L8 (and 100109 L10 only if outside business hours) |
| 2 | Add to `Domain-Admins-Custom` (`Add-ADGroupMember`) | 100105 L10, then **100111 L12** |
| 3 | RDP logon as `SOCLAB\svc-chain03` from your PC (new `mstsc` window — a user-switch inside an admin session gives type 2, not type 10) | 92653 L3, then **100112 L14** |

Check each alert in Threat Hunting (alert-list view, rule name and level visible). If 100111 fires but 100112 does not, the break is in the second link — see troubleshooting. If neither fires, start at the first link.

**Negative tests — these must stay silent:**

- Add an **old** account (created days ago) to `Domain-Admins-Custom` → 100105 fires, **100111 must not** (no recent 4720 for that account).
- Add a **new** account to a normal group (`GG-Sales`) → 60141 fires, **100105 and 100111 must not**.
- Create a new account and log on with it **without** the group add → no 100111, **no 100112**.

One negative test without the other proves nothing — same discipline as Lab 01.

## Troubleshooting — if the rules do not fire

Work the chain link by link. The most likely break is the first one.

**1. `same_user` may not align across the three events.** This is the open question in this design. `<same_user />` compares the `user` field of the two events. If Wazuh's `user` field on a 4720/4728 alert is the *subject* (the administrator who performed the action) while on a 4624 alert it is the *target* (the account logging on), the two will never match and the correlation can never fire. Diagnose it in Threat Hunting: add `user` as a Discover column and read the `user` value on a 60109 alert, a 100105 alert, and a 92653 alert for the same test account. If they disagree, that is the answer — and the fix is to drop `<same_user />` and accept the wider net (timeframe only), or to scope the rule differently. Do not guess; read the field.

**2. Wrong parent for the logon step.** 100112 chains on **92653**, the RDP-specific rule. A console logon (type 2) or a network logon (type 3) will not match 92653, so 100112 will not fire — that is a known scope limit, not a bug. If the test logon was not type 10, the rule correctly stayed silent. (A broader variant could chain on 60106, the generic logon-success rule — but 60106 fires on every 4624, including SYSTEM and computer accounts, so that variant needs the human-only filter and will be noisier.)

**3. Timeframe.** Both links allow one hour. If the test steps ran more than an hour apart, the chain expired. Re-run the steps inside the hour, or widen `timeframe` — and note the trade-off in the README when you do.

**4. Rules not loaded.** Re-run the config test and the `wazuh-logtest` check on a captured 4728 event (the Lab 01 commenter's tip, still open from the chain lab): feed the event to logtest and read which rule wins. If 100111 does not appear in the logtest output, the ruleset did not pick the rules up.

**5. The 100105 dependency.** If 100105 is disabled or removed, 100111 loses its parent and goes blind. Verify 100105 still fires on the privileged 4728 first, then debug the correlation.

## Threat Hunting in Wazuh

Paste into the search bar (Events tab) over the lab time window:

**100111 — new account, privileged group:**
```
rule.id: 100111
```

**100112 — the full chain in one alert:**
```
rule.id: 100112
```

**The chain for one account, all links:**
```
data.win.eventdata.targetUserName: svc-chain03 AND (rule.id: 60109 OR rule.id: 100105 OR rule.id: 100111 OR rule.id: 92653 OR rule.id: 100112)
```

## Open items

- **These rules are untested.** Status changes only after the chain test above runs and the alerts are observed.
- **Durable pack sync:** rules **100109 and 100110 are not in the durable pack file** (`local_rules.xml` in the goal workspace) — verified Nov 7, 2026; only 100100–100108 are there. Syncing them (and eventually 100111/100112) into the pack is a separate job.
- **`wazuh-logtest` check for 100105 vs 60141** is still open from the chain lab — the same technique applies to 100111/100112 once they are loaded.
- **Scope limit:** 100112 only covers RDP (type 10) logons. Console and network logons need their own variants if that coverage is wanted.
