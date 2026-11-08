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

### [Lab 04 — Logon Tuning Rules (100113 & 100114)](Lab-04-Logon-Tuning-100113-100114/)

Two rules that split the 4624 flood by privilege: **100113** (a high-privilege account logged on, Administrator SID `-500`, level 10) and **100114** (a normal human user logged on, level 5, machine accounts excluded). Covers logon types 2, 3 and 10. **Status: TESTED Nov 8–9, 2026** — all three logon types verified for both tiers (Admin type 10 at 01:15:32, svc-chain02 type 10 at 01:17:29, after `logoff` + fresh RDP); DWM flood fixed with four SID negates, UMFD-2 fixed with a `^UMFD-` negate, new 92653-style descriptions render correctly, 60106 silent on human logons, 92653 shadowed (last fired Nov 8 18:08). Includes the honest limit: SID matching catches the Administrator account, not privileged-group members — the 4672-correlation follow-up is the fix for that.

### [Lab 05 — Off-Hours Logon Rules (100115 & 100116)](Lab-05-Off-Hours-Logon-Rules-100115-100116/)

Two rules that split logons by **time**: **100115** (any human account logging on outside business hours, 4624, level 12) and **100116** (a failed logon outside business hours, 4625, level 8, child of 60122). Same `5 pm - 8 am` UTC window as 100109. **Status: TESTED Nov 9, 2026** — 100115 fired on an off-hours Administrator logon (01:40:39, type 3); 100116 fired on off-hours failed logons for svc-chain02 and Administrator (02:07–02:18); the time-flip test proved 60122 fires again on-hours (02:28–02:31). Includes the failed-RDP lesson (a failed logon is always type 3, never type 10) and the lockout policy found during testing (5 attempts, 30-minute lockout). Open items: a type-10 firing under 100115 is still pending, and the Kali-side revert of the time-flip test needs verification.

## The master reference

**[06-Custom-Detection-Rules-Reference](../06-Custom-Detection-Rules-Reference/)** — one file per rule for all 17 custom rules (100100–100116): exact XML, purpose, line-by-line explanation, shadowing, test evidence or test plan, DQL query, and MITRE mapping. Start here to *find* a rule; read the lab folders above to learn *how* it was built. The reference also carries the full shadowing map — including the broken dependency: rule 100112 chains on 92653, which is now shadowed by 100113/100114 and needs re-parenting before its test.

## Key lessons across all five labs

- **Tuning pattern:** broad built-in → narrow dangerous subset → louder alert.
- **Always test both directions:** positive (should fire) and negative (should stay silent).
- **Names are fragile, SIDs are stone.** Match on what attackers can't easily change.
- **Boundary-test every rule.** Know exactly where your detection works and where it goes blind.
- **Correlation chains on what actually fires.** A parent rule that is shadowed can never trigger its children — check the chain link by link.
- **Split the flood by exclusion, not by volume.** A human-only rule is built by excluding machine accounts, not by raising the level on everything.
- **Time is a detection dimension, not just a timestamp.** The same logon at noon and at 3 AM are different alerts — off-hours rules (100109, 100115, 100116) fire on the timing, and the window is evaluated against the manager's UTC clock, not local time.
- **A child rule suppresses its parent — and the parent is the fallback.** 100116 silences 60122 during off-hours, and 60122 fires again on-hours. Check what does *not* fire, not just what does.
- **A failed logon never creates a session.** A failed RDP attempt is always type 3, never type 10 — so a type-10 filter will never catch a failed logon, and `logoff` cannot fix it. Filter on the rule, not the logon type.
- **Reconnecting is not logging on.** A missing type 10 usually means the session already exists — check `query session` before blaming the rule.
