# Lab 07 — Alert Triage SOP: What To Do When an Alert Arrives

*Part of the [Core Detection Labs](../README.md) — the playbook that turns Lab 05's five alerts, Lab 06's evasion lessons, and Lab 03's correlation rules into a repeatable analyst workflow. Written for an L1 analyst on this home lab; the same steps scale to a real SOC queue.*

---

## Overview

A detection is not a verdict. Every alert in this lab — from a level 3 logon to a level 14 full-chain correlation — needs the same discipline: read the alert, scope it, verify it against the evidence, then decide. This SOP is that discipline, written down.

It covers the alerts this lab actually produces:

| Rule | Level | Event | What it is |
|---|---|---|---|
| 100112 | 14 | 4624 (via 100111) | Full chain in one alert — new account, privileged group, RDP logon |
| 100111 | 12 | 4728 (via 100105) | New account added to a privileged group within 1 hour |
| 100108 | 12 | 1102 | Audit log cleared (possible defense evasion) |
| 100105 | 10 | 4728 | Member added to a privileged group (possible privilege escalation) |
| 100109 | 10 | 4720 | Account created outside business hours (possible backdoor) |
| 100110 | 10 | 4738 | Built-in Administrator account (RID 500) modified (possible persistence) |
| 60109 | 8 | 4720 | User account enabled or created |
| 92653 | 3 | 4624 type 10 | RDP logon |
| 67027 | 3 | 4688 | A process was created |
| 60106 | 3 | 4624 (any) | Windows Logon Success — floods, triage by exception |
| Sysmon 11 | 15 | Sysmon FileCreate | Usually the PowerShell policy-test file — a known false positive |

**Scope, stated honestly:** this SOP is written for a one-person home lab. There is no second team to hand off to. "Escalate" here means: stop routine triage, preserve evidence, and investigate deeper — not file a ticket to someone else. The escalation section says exactly that.

**Environment facts the SOP depends on:** domain `soclab.local` (`SOCLAB`), domain controller `WIN-SOCLAB` (`192.168.100.146`), analyst PC `192.168.100.27`, Wazuh 4.14.5 on Kali (`192.168.100.50`), agent 001. **The Wazuh manager clock is UTC** — alert times in Threat Hunting are UTC, five hours behind PKT. A 14:55 PKT lab event shows as 09:55 UTC. Always convert before deciding whether an "off-hours" rule should have fired.

**Two rules of the dashboard, before anything else:**

1. **Threat Hunting shows the alerts index only.** If an event fired no rule, it is invisible here. For the raw event, use the archives index or `Get-WinEvent` on the DC.
2. **Severity ≠ certainty.** A Sysmon 11 FileCreate fired at level 15 in Lab 05 and was PowerShell's own startup test — benign. A level 3 logon can be the loudest thing in the queue when it is the third link of a chain. Read the evidence, not the number.

---

## 1. The triage flow — every alert, same five steps

Do these in order. Do not skip Step 2 to jump to a verdict — most wrong verdicts in this lab come from deciding on the alert row alone.

### Step 1 — Acknowledge: open the alert, read the document

1. In the Wazuh dashboard, open **Threat Hunting → Events tab**.
2. Click the alert row to open the **document** (detail view). The alert list shows rule name and level; the document shows the evidence.
3. Record the basics before anything else (see [Section 5](#5-documentation--what-to-record-for-every-triaged-alert)): rule, level, event ID, `eventRecordID`, time (UTC and PKT), account, source IP.

**What to look for first:** the account name, the source IP, and the logon type. Those three fields decide whether this is a five-minute close or a full investigation.

### Step 2 — Scope: is this alert part of a chain?

Before judging the alert alone, check whether the same account appears in other alerts. One account ties Lab 05's whole chain together — `svc-chain02`, SID ending `-1141` — and the same test works on any alert.

Run the whole-chain query for the account named in the alert (replace the account name):

```
(data.win.eventdata.targetUserName: svc-chain02 OR data.win.eventdata.subjectUserName: svc-chain02)
```

Note the two fields: most events record the account as `targetUserName`, but 4688 records it as `subjectUserName`. A query on one field alone misses the process-creation link.

Then check the Logon ID. A process created inside an RDP session shares the session's Logon ID — in Lab 05, the RDP logon and the `notepad.exe` creation both carry Logon ID `0x222F38`. If the alert's Logon ID matches another alert's, they are one session, one story — triage them together, not separately.

**Decision point:** if the account shows up in two or more steps of the chain (created → privileged group → logon → process → log cleared), stop treating the alert as a single event. Work the incident, starting with the highest-level alert (usually 100112 or 100108), and use the per-alert playbooks below for each link.

### Step 3 — Verify: answer the three questions

Every alert must answer three questions before a verdict. The per-alert playbooks in Section 2 list the exact three for each rule; the generic versions are:

1. **Who?** Which account, and is it known? A new account with no owner and no baseline is suspicious by itself. Check the SID — names can be renamed, SIDs cannot (the Lab 02 lesson: renaming `Administrator` to `Administratorss` evaded a name-based rule; the SID `-500$` did not).
2. **From where?** Which source IP, and is it expected? In this lab, `192.168.100.27` is the analyst's own PC and `127.0.0.1` is a console logon on the DC itself. An IP outside the lab range is an escalation trigger (see [Section 4](#4-escalation-criteria--when-an-l1-stops-and-investigates-deeper)).
3. **When?** What time (UTC), and does it fit the pattern? A 4720 at 09:55 UTC is daytime — rule 100109 correctly stays silent. A 4720 at 01:40 UTC is off-hours — 100109 should fire, and if it did not, the rule is not loaded (see the 100109 playbook).

### Step 4 — Decide: true positive, false positive, or escalate

Three verdicts only. "Maybe" is not a verdict — if you cannot decide, the verdict is **escalate** (deeper investigation), not "leave it open".

- **True positive:** the evidence matches an attack step. A new account, added to a privileged group, logging on over RDP within the hour is a true positive at every link — and the correlation rule 100112 should have fired on top of it. Go to containment (Section 2, per-alert "what to do next").
- **False positive:** the evidence matches a known benign pattern. The known ones in this lab are listed in every playbook below — the Sysmon policy-test file, the 60106 flood, the daytime 4720, the `WIN-SOCLAB$` computer-account logons. Close it as a false positive **with a note** saying which pattern matched and what you checked. A false positive closed without a note is a guess, and the next analyst will re-triage the same alert.
- **Escalate:** anything in [Section 4](#4-escalation-criteria--when-an-l1-stops-and-investigates-deeper). In this lab, escalation means: stop, preserve evidence, investigate deeper.

### Step 5 — Document: write it down the same way every time

Record the fields in [Section 5](#5-documentation--what-to-record-for-every-triaged-alert). The point of the record is that the next alert for the same account is triaged in seconds, not minutes — the history does the scoping for you.

---

## 2. Per-alert playbooks

Each playbook follows the same shape: severity, what it means, the first three questions, the exact queries, true positive vs false positive, and what to do next. Work the playbooks in priority order (Section 3), not in the order the alerts arrived.

### 100112 — the full chain in one alert (level 14)

**Severity:** Critical. The highest-priority alert in this lab.

**What it means in one line:** a brand-new account was added to a privileged group and then logged on over RDP, all within the hour — the whole account-lifecycle chain, in a single alert.

**First three questions:**

1. Which account — and was it created today? (Check the 4720 for the same account.)
2. Which privileged group was it added to?
3. Which source IP logged on, and is it the lab range?

**Queries:**

```
rule.id: 100112
```

```
data.win.eventdata.targetUserName: svc-chain03 AND (rule.id: 60109 OR rule.id: 100105 OR rule.id: 100111 OR rule.id: 92653 OR rule.id: 100112)
```

(Use the second query with the real account name from the alert — `svc-chain03` is the Lab 03 test name. It shows every link of the chain for that account in one view.)

**True positive vs false positive:** a 100112 firing on an account created within the hour, added to a privileged group, then logging on over RDP is a true positive. There is no known benign pattern for this rule — the correlation exists precisely because the sequence has no innocent explanation in this lab. If 100112 fires but one of the links is missing from the query results, check whether the missing link's rule is loaded before doubting the alert (see the Lab 03 troubleshooting: `same_user` alignment, the one-hour timeframe, and the 100105 dependency).

**What to do next:** escalate immediately (Section 4). Then work the chain backwards: confirm the 4720, the 4728, and the 4624, note the Logon ID, and check what the account did after the logon — run the 4688 query for the account:

```
data.win.system.eventID: 4688 AND data.win.eventdata.subjectUserName: svc-chain02
```

(Replace the account name.) Containment in this lab: disable the account, remove it from the privileged group, and preserve the Wazuh evidence before any cleanup — the DC's local log can be cleared by the attacker, the SIEM copy cannot.

> **Status note:** rules 100111 and 100112 are **UNTESTED** (Lab 03). They are written from Wazuh's documented rule syntax and have not yet fired in the lab. A 100112 alert has never been observed here. If you see one, it is either the first successful test of Lab 03 — or a rule misconfiguration. Verify the links (the second query above) before acting, and record the outcome either way: the first observation is what turns this rule from untested to verified.

### 100111 — new account added to a privileged group (level 12)

**Severity:** High.

**What it means in one line:** an account created within the last hour was just added to a privileged group.

**First three questions:**

1. How old is the account — was the 4720 within the last hour?
2. Which privileged group?
3. Has the account logged on yet? (If yes, 100112 should also have fired — check.)

**Queries:**

```
rule.id: 100111
```

```
data.win.eventID: 4720 AND data.win.eventdata.targetUserName: svc-chain03
```

(Second query with the real account name, to confirm the creation time and the one-hour window.)

**True positive vs false positive:** a 100111 on a fresh account and a privileged group is a true positive — this is the privilege-escalation moment of the chain. The false-positive case is an old account: if the account was created days ago, 100111 must not fire (that is its Lab 03 negative test). If it fired on an old account, the correlation is misbehaving — check the timeframe and the `same_user` alignment in Lab 03 before trusting the next 100111.

**What to do next:** check for the logon immediately — run `rule.id: 100112` and the RDP query for the account:

```
data.win.system.eventID: 4624 AND data.win.eventdata.targetUserName: svc-chain03 AND data.win.eventdata.logonType: 10
```

If the account has already logged on, work it as a 100112 (above). If it has not, the window is still open: watch the account, and treat any logon from it as the next link, not a new incident.

### 100105 — member added to a privileged group (level 10)

**Severity:** High.

**What it means in one line:** someone was added to a privileged group — a possible privilege escalation.

**First three questions:**

1. Which group — and is it on the privileged list (`Domain Admins`, `Enterprise Admins`, `Administrators`, `Schema Admins`, `Domain-Admins-Custom`)?
2. Who was added — a user, or a whole group nested in (Lab 01's nesting test: a group added to a privileged group fires this rule too)?
3. How old is the account that was added — new (check the 4720), or existing?

**Queries:**

```
rule.id: 100105
```

```
data.win.system.eventID: 4728 AND data.win.eventdata.targetUserName: Domain-Admins-Custom
```

```
data.win.system.eventID: 4728 AND data.win.eventdata.memberName: *svc-chain02*
```

```
rule.id: 60141
```

The last query is the shadowing check: with the custom rules loaded, 100105 fires on privileged adds and 60141 stays silent. If 60141 fires on a privileged add, the custom rule is not loaded — fix the ruleset before trusting the absence of 100105 alerts.

**True positive vs false positive:** a 100105 on a privileged group is a true positive by design — the rule only fires on the privileged list. The "false positive" version of this alert is a 100105 on an account the analyst recognizes as a legitimate, planned change (a real admin doing a real task). In that case the verdict is "expected change", and the note must say who approved it. An unexplained 100105 is never closed as a false positive on the grounds that "the group add looked routine" — a routine-looking group add is exactly what the chain does.

**What to do next:** check the account's age (the 4720 query in the 100111 playbook). New account + privileged group = work it as a 100111. Existing account + privileged group = confirm with the change owner; if no owner exists, escalate.

### 100108 — audit log cleared (level 12)

**Severity:** Critical.

**What it means in one line:** the Security log was cleared — possible defense evasion, and the local evidence is gone.

**First three questions:**

1. Who cleared it — which subject account, and which Logon ID?
2. What happened just before the clear — which account's alerts stop at the clear time?
3. Is the Wazuh copy intact? (It should be — Wazuh indexed the events before the clear.)

**Queries:**

```
rule.id: 100108
```

```
data.win.system.eventID: 1102
```

**True positive vs false positive:** a 1102 in this lab is a true positive. There is no routine reason to clear the Security log on the DC, and no known benign pattern for it here. The one thing that is *not* a false positive but a trap: the clear itself does not name the backdoor account. In Lab 05 the 1102 subject was `administrator`, not `svc-chain02` — the filtered token forced the clear to run from the admin session. Do not close the investigation because the clear "was done by administrator" — that is the lab's own behavior, and the account tie breaks at this step by design.

**What to do next:** escalate immediately (Section 4). Work backwards from the clear time: list every alert for the hour before it, and treat them as one incident. Do not try to verify anything on the DC's local log — it is empty by design. The evidence lives in Wazuh.

### 100109 — account created outside business hours (level 10)

**Severity:** High — when it fires.

**What it means in one line:** an account was created between 5 pm and 8 am UTC — outside business hours, a possible backdoor.

**First three questions:**

1. What time was the creation — in UTC, not PKT? (The manager clock is UTC; convert before judging.)
2. Who created it — and is the creator a known admin?
3. Was the account created for a known purpose, or is it unexplained?

**Queries:**

```
rule.id: 100109
```

```
rule.id: 60109 AND data.win.system.eventID: 4720
```

**True positive vs false positive:** a 100109 firing on an unexplained off-hours creation is a true positive. The common "false alarm" here is not a false positive at all — it is the rule *not* firing. A 4720 at 09:55 UTC (14:55 PKT) is daytime, and 100109 correctly stays silent; Lab 05 proved this by accident. Do not write "100109 failed to fire" in the record for a daytime creation — write "creation outside the off-hours window, 100109 correctly silent". The rule is time-based; judge it by the UTC clock.

**What to do next:** check what the new account did next — the privileged-group query and the logon query from the 100105 and 100111 playbooks. An off-hours creation that gains privilege within the hour is the chain, and 100111 should fire on it.

### 100110 — built-in Administrator modified (level 10)

**Severity:** High.

**What it means in one line:** the built-in Administrator account (RID 500) was changed — possible persistence.

**First three questions:**

1. What changed — display name, description, profile path, UAC setting, or something else? (4738 only shows Changed Attributes for tracked attributes; `givenName`/`sn` changes show all "-".)
2. Who made the change?
3. Was the change planned?

**Queries:**

```
rule.id: 100110
```

```
data.win.system.eventID: 4738
```

**True positive vs false positive:** a 100110 on an unexplained change to the Administrator account is a true positive. A planned change (a documented rename, a profile-path update by the lab owner) is an expected change — close it with a note naming the change and who made it. Do not match on the name `Administrator` when investigating: the account was renamed to `Administratorss` during Lab 02 testing and a name-based rule went blind. Match on the SID (`-500$`) — names are fragile, SIDs are stone.

**What to do next:** check whether the Administrator account was used afterwards — the logon query with the account name, and whether any new account appeared around the same time. A modified Administrator plus a new account in the same window is two persistence moves, not two separate alerts.

### 92653 — RDP logon (level 3)

**Severity:** Low alone, high in context.

**What it means in one line:** an account logged on over RDP (type 10) from a real source IP.

**First three questions:**

1. Which account — and how old is it?
2. Which source IP — the analyst's PC (`192.168.100.27`), or somewhere else?
3. What did the session do — which processes were created under its Logon ID?

**Queries:**

```
rule.id: 92653 AND data.win.eventdata.targetUserName: svc-chain02
```

```
data.win.system.eventID: 4624 AND data.win.eventdata.targetUserName: svc-chain02 AND data.win.eventdata.logonType: 10
```

**True positive vs false positive:** a 92653 for the analyst's own account, from the analyst's own PC, during lab work is expected activity — close it with a note saying so. A 92653 for a brand-new privileged account, or from an IP outside the lab range, is a true positive and the third link of the chain. The trap is the logon type: a console logon (type 2, `127.0.0.1`) and a network logon (type 3) never fire 92653 at all — if the account logged on but no 92653 exists, check the logon type before concluding "no RDP happened".

**What to do next:** follow the Logon ID. Run the 4688 query for the account (subjectUserName) and compare `SubjectLogonId` with the logon's Logon ID. Same ID = the processes belong to this session. A new account's first RDP logon plus any process creation under it is the chain — check `rule.id: 100112`.

### 67027 — a process was created (level 3)

**Severity:** Low alone, high in context.

**What it means in one line:** a process started on the DC.

**First three questions:**

1. Which process — and which parent launched it?
2. Which account and Logon ID — does it match a recent RDP logon?
3. Is the process expected on this machine?

**Queries:**

```
rule.id: 67027 AND data.win.eventdata.subjectUserName: svc-chain02
```

```
data.win.system.eventID: 4688 AND data.win.eventdata.subjectUserName: svc-chain02
```

**True positive vs false positive:** 67027 fires on *every* 4688 — the detection is process creation, not the process name. A `notepad.exe` launched by a test account in the lab is expected activity. The signal is the parent-child pair and the account: a process under a brand-new privileged account, inside a fresh RDP session, is the chain's fourth link. Do not triage on the filename — an attacker runs anything except `notepad.exe`, and the rule fires the same way. Read the parent, the account, and the Logon ID instead.

**What to do next:** match the Logon ID to the RDP logon. If it matches a recent type 10 logon by a new privileged account, work it as part of the chain (100112 check). If the process is a living-off-the-land binary (`rundll32.exe`, `mshta.exe`, `regsvr32.exe`) under an unknown account, escalate — that is the process, not the lab stand-in.

### 60106 — Windows Logon Success, the flood (level 3)

**Severity:** Low. Triage by exception, never row by row.

**What it means in one line:** a logon succeeded — and this rule fires on *every* 4624, so the list is flooded.

**First three questions:**

1. Am I looking at the raw list, or the filtered list? (Never triage the raw list.)
2. After the human-only filter, is there a logon I do not recognize?
3. Is there a first logon by a newly created account?

**Queries:**

The raw flood (for counting only — do not triage from this):

```
rule.id: 60106
```

The working query — human logons only. Computer accounts (names ending in `$`, like `WIN-SOCLAB$`), `SYSTEM`, and services are dropped:

```
data.win.system.eventID: 4624 AND data.win.eventdata.logonType: 10 AND NOT data.win.eventdata.targetUserName: *$ AND NOT data.win.eventdata.targetUserName: SYSTEM
```

**True positive vs false positive:** the flood itself is the false positive — `WIN-SOCLAB$` 4624 rows, `SYSTEM` logons, and service logons are computer-account noise, not incidents. They are closed in bulk by the filter, not one by one. A true positive in this list is a human logon that survives the filter and does not belong: a new account's first logon, a logon from an unknown IP, a logon at an unusual hour. If the filtered list is empty, the correct record is "filtered list reviewed, no unrecognized human logons" — not "60106 reviewed".

**What to do next:** add `data.win.eventdata.targetUserName`, `data.win.eventdata.logonType`, and `data.win.eventdata.ipAddress` as columns in Discover / Threat Hunting, so every row shows the account, the logon type, and the source IP without opening the document. Then triage the survivors with the 92653 playbook.

### Sysmon 11 — the policy-test file (level 15, usually a false positive)

**Severity:** Verify first, close fast. The level is the trap.

**What it means in one line:** a file was created — and in this lab, most of the time, the file is PowerShell's own startup test.

**First three questions:**

1. What is the filename — is it `__PSScriptPolicyTest_*.ps1`?
2. What is the Image — is it `powershell.exe`?
3. What is the path — is it the user's `Temp` folder?

**Queries:**

Filter the alerts index to the Sysmon channel, event 11, and read the filename and Image from the document. (The Wazuh rule ID for this Sysmon alert is not recorded in the lab notes — find it by the event, not by a rule number.)

```
data.win.system.eventID: 11
```

Then open the document and check the channel is `Microsoft-Windows-Sysmon/Operational`, the Image, and the target filename.

**True positive vs false positive:** `__PSScriptPolicyTest_*.ps1` in `Temp`, created by `powershell.exe`, is PowerShell's own execution-policy test — a benign false positive. It fired at level 15 in Lab 05 because a `.ps1` in Temp is an attacker pattern; the filename is the tell. Close it as a false positive with a note naming the filename. A real 11 is everything else: an executable dropped in `Temp`, `AppData`, or a Startup folder, a `.ps1` with a name that is not the policy test, or a file created by an unknown process. Those escalate.

**What to do next:** if it is the policy test, close it and move on — do not let a level 15 row eat the triage session. If it is not, treat the file as a dropped artifact: note the full path, the creating process, and the account, and escalate.

---

## 3. Severity and priority table

Work alerts in this order, not in arrival order. A level 3 that completes a chain outranks a level 10 that stands alone.

| Priority | Rule | Level | One-line reason |
|---|---|---|---|
| 1 | 100112 | 14 | The whole chain in one alert — new account, privileged group, RDP logon |
| 2 | 100108 | 12 | Log cleared — anti-forensics, and the local evidence is already gone |
| 3 | 100111 | 12 | New account reached a privileged group — the privilege moment |
| 4 | 100105 | 10 | Privileged-group add — escalation in progress |
| 5 | 100109 | 10 | Off-hours account creation — the backdoor being built |
| 6 | 100110 | 10 | Built-in Administrator modified — persistence on the most powerful account |
| 7 | 60109 | 8 | Any account created — the first link, worth a look every time |
| 8 | 92653 | 3 | RDP logon — low alone, the third link in context |
| 9 | 67027 | 3 | Process created — low alone, the fourth link in context |
| 10 | 60106 | 3 | Logon flood — triage the filtered survivors only |
| 11 | Sysmon 11 (policy test) | 15 | Highest level, usually benign — verify the filename first, close fast |

**Why the level 15 sits last:** priority is not level. The policy-test file is the most common level 15 in this lab and it is benign; it is checked first in wall-clock time (thirty seconds, filename check) and last in priority because it almost never needs anything after the check.

---

## 4. Escalation criteria — when an L1 stops and investigates deeper

In a real SOC, escalation means handing the incident to a senior analyst or an incident-response team. **This lab has one person.** Escalation here means: stop routine triage, preserve evidence, and investigate deeper — the same decision, without the handoff. Do not pretend a handoff exists, and do not keep triaging single alerts once any criterion below is met.

**Escalate immediately when any of these is true:**

1. **100112 fires.** The full chain has already happened. Work the incident, not the alert.
2. **100108 fires.** The log was cleared. Evidence on the DC is gone; the investigation runs on the Wazuh copy, and every alert from the hour before the clear is part of the incident.
3. **100111 fires for an account nobody recognizes.** A new account reaching a privileged group is the chain's second link — check for the logon before deciding it stopped there.
4. **A logon comes from an IP outside the lab range.** The lab's known sources are `192.168.100.27` (the analyst's PC), `127.0.0.1` (console on the DC), and the DC itself (`192.168.100.146`). Anything else is unknown until proven otherwise.
5. **A privileged account is involved and unexplained.** `Administrator`, any member of `Domain-Admins-Custom`, or an account whose SID ends in `-500` — if the activity has no owner and no change record, it is not routine.
6. **The same account appears in two or more chain steps.** One alert is a detection; two links are an incident. Stop single-alert triage and work the chain.
7. **A Sysmon 11 is not the policy-test file.** An executable or script dropped in `Temp`, `AppData`, or a Startup folder by an unknown process is a dropped artifact until proven otherwise.

**What "investigate deeper" means in this lab, concretely:**

1. **Preserve first.** Do not clean up, delete accounts, or clear anything until the evidence is recorded — the chain's proof is the Wazuh copy, and cleanup generates its own events (4726, 4729) that mix into the timeline.
2. **Hunt the account.** Run the whole-chain query for the account (Section 1, Step 2) and list every alert it appears in, in time order.
3. **Hunt the Logon ID.** Every 4688 with the same `SubjectLogonId` as the RDP logon belongs to that session — list them all.
4. **Check for persistence.** Look for the account in other privileged groups, for 4738 changes, and for scheduled tasks or Run keys if the lab covers them yet. A backdoor account is only one persistence move.
5. **Decide containment, then do it.** In this lab, containment is: disable the account, remove it from the privileged group, and revoke the RDP path. Then verify in Threat Hunting that no new alerts arrive for the account.
6. **Write it up.** The documentation in Section 5 is the incident record. An investigation with no record did not happen.

---

## 5. Documentation — what to record for every triaged alert

Same fields, every alert, no exceptions. The record is what makes the next alert for the same account fast.

| Field | What to write | Where it comes from |
|---|---|---|
| Rule | Rule ID and level (e.g. `100105`, L10) | Alert list row |
| Event | Event ID (e.g. `4728`) | Alert document |
| Time | UTC and PKT (e.g. `01:40:41 UTC / 06:40:41 PKT`) | Alert document — remember the manager clock is UTC |
| Account | `targetUserName` or `subjectUserName` (4688 uses subject) | Alert document |
| SID | Account SID, or at least its ending (e.g. `-1141`, `-500`) | Alert document — SIDs, not names, survive renames |
| Source IP | `ipAddress` (for 4624) | Alert document |
| Logon ID | Logon ID (e.g. `0x222F38`) for 4624 and 4688 | Alert document — the value that ties a session together |
| Logon type | `logonType` (2 console, 3 network, 10 RDP) | Alert document |
| Verdict | True positive / false positive / escalate | Your decision, with the reason |
| Evidence checked | Which queries you ran, and what they returned | Threat Hunting — paste the query, not a summary of it |
| Action taken | Contained / watched / closed as FP / escalated | What you did, not what you planned |
| Follow-up | What still needs doing (e.g. "Lab 03 test pending", "logtest check open") | The open items that survive the triage |

**Three documentation rules:**

1. **Record the query, not the conclusion.** "Ran `rule.id: 100105`, one hit, svc-chain02 → Domain-Admins-Custom" is evidence. "Checked the group add" is not.
2. **Record the UTC time.** The manager clock is UTC and the lab notes are PKT. A record without a timezone is a record that will confuse the next person — including you, next week.
3. **Record false positives with the pattern that matched.** "FP — `__PSScriptPolicyTest` file, powershell.exe, Temp" lets the next analyst close the same alert in seconds. "FP" alone forces them to re-triage it.

---

## How to use this SOP

1. **First time:** read Section 1 once, end to end. It is the only section that applies to every alert.
2. **On shift (or on lab day):** open Section 3, work the queue in priority order, and open the matching playbook in Section 2 for each alert.
3. **When stuck:** the verdict is escalate (Section 4). "Cannot decide" is a decision — investigate deeper.
4. **After the lab:** the record in Section 5 is the portfolio. A triaged alert with a verdict, a query, and a follow-up is interview evidence; an alert with no record is just a screenshot.

---

*Part of [Wazuh Home SOC Lab](../../README.md) — Lab 05 is the chain, Lab 06 is the same chain with the attacker fighting back, Lab 03 is the rule that fires on the whole sequence, and this lab is what the analyst does when any of them fires.*
