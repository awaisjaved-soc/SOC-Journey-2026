# 03 — Custom Detection Rules

*Part of the [Wazuh Home SOC Lab](../README.md). After mapping 27 Windows events to Wazuh's built-in rules ([02-Account-Management-27-Events](../02-Account-Management-27-Events/)), the next step was writing my own.*

---

These labs follow one pattern: **find where the built-in rules are too broad, write a narrower rule that fires louder on the dangerous subset, then prove it works with positive and negative tests.**

## Labs

### [Lab 01 — Privileged Group Monitoring (100105)](Lab-01-Privileged-Group-Monitoring-100105/)

Custom rule that fires at level 10 when anyone is added to a privileged group (built-in 60141 only fires at level 5 for all groups equally). Includes the **shadowing experiment** — proving the custom rule suppresses the built-in rule on match — and a nesting test.

### [Lab 02 — Tuning Noisy Rules (100109 & 100110)](Lab-02-Tuning-Noisy-Rules-100109-100110/)

Two rules I wrote myself for the "needs tuning" verdicts: **100109** (account created outside business hours, MITRE T1136) and **100110** (built-in Administrator modified, MITRE T1098). Includes the **rename discovery** — I accidentally evaded my own rule by renaming the Administrator account, then fixed it by matching on SID instead of name.

### [Lab 03 — Account-Lifecycle Anomaly Rules (100111 & 100112)](Lab-03-Account-Lifecycle-Anomaly-Rules/)

Two correlation rules that catch the whole chain in one alert: **100111** (new account added to a privileged group within an hour of creation, level 12) and **100112** (that new privileged account logging on via RDP within an hour, level 14). Built on the shadowing lesson — 100111 chains on 100105, not on 60141, because 60141 never fires on privileged 4728s. **Status: untested** — written from the documented syntax, awaiting the lab run.

## Key lessons across all three labs

- **Tuning pattern:** broad built-in → narrow dangerous subset → louder alert.
- **Always test both directions:** positive (should fire) and negative (should stay silent).
- **Names are fragile, SIDs are stone.** Match on what attackers can't easily change.
- **Boundary-test every rule.** Know exactly where your detection works and where it goes blind.
- **Correlation chains on what actually fires.** A parent rule that is shadowed can never trigger its children — check the chain link by link.
