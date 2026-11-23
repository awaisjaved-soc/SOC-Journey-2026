# Custom Detection Rules — Master Reference

*Part of the [Wazuh Home SOC Lab](../README.md). Every custom rule I have written for this lab, in one place, each with its exact XML, its purpose, how it works, what it shadows, and whether it has actually fired in the lab.*

---

## Why this folder exists

The rules were built across five labs in [03-Custom-Detection-Rules](../03-Custom-Detection-Rules/) — one folder per lab, each with its own story. That is the right place to learn *how* a rule was built. This folder is the right place to **find** a rule: one file per rule, same shape every time, so any rule can be checked, copied, or audited without digging through lab narratives.

The rule pack that ships these rules to the manager lives in the goals workspace (`custom-detection-rules/local_rules.xml`, rules 100100–100108). The Lab-03/04/05 folders hold the newer rules (100111–100116). This folder documents all of them; it does not replace those sources.

## Rule index

| Rule | Level | Event(s) | Purpose (one line) | Status | Lab |
|---|---|---|---|---|---|
| [100100](Rule-100100-Brute-Force.md) | 10 | 4625 | 8 failed logons in 120 seconds — brute force | UNTESTED | Pack |
| [100101](Rule-100101-RDP-Brute-Force.md) | 10 | 4625 (type 10) | 8 failed RDP logons in 120 seconds — RDP brute force | UNTESTED | Pack |
| [100102](Rule-100102-Kerberoasting.md) | 12 | 4769 | RC4-encrypted service ticket — Kerberoasting | **TESTED** | Lab 09 |
| [100103](Rule-100103-LSASS-Access.md) | 3 | Sysmon 10 | Base telemetry: A process opened LSASS handle — audit logging | **TESTED** | Lab 15 |
| [100104](Rule-100104-New-Service.md) | 8 | 7045 | A new service was installed — persistence | UNTESTED | Pack |
| [100105](Rule-100105-Privileged-Group.md) | 10 | 4728 / 4732 / 4756 | Account added to a privileged group — privilege escalation | **TESTED** | Lab 01 |
| [100106](Rule-100106-NewCredentials-Logon.md) | 10 | 4624 (type 9) | NewCredentials logon — RunAs / possible pass-the-hash | UNTESTED | Pack |
| [100107](Rule-100107-Network-Logon-High-Value.md) | 8 | 4624 (type 3) | Network logon to Administrator / krbtgt — lateral movement | UNTESTED | Pack |
| [100108](Rule-100108-Audit-Log-Cleared.md) | 12 | 1102 | Audit log was cleared — defense evasion | **TESTED** | Pack (chain lab) |
| [100109](Rule-100109-Off-Hours-Account-Creation.md) | 10 | 4720 | Account created outside business hours — backdoor | **TESTED** | Lab 02 |
| [100110](Rule-100110-Administrator-Modified.md) | 10 | 4738 | Built-in Administrator modified — persistence | **TESTED** | Lab 02 |
| [100111](Rule-100111-New-Account-Privileged-Group.md) | 12 | 4720 → 4728 | New account added to a privileged group within 1 hour | UNTESTED | Lab 03 |
| [100112](Rule-100112-Full-Chain-RDP-Logon.md) | 14 | 4728 → 4624 (type 10) | New privileged account logged on via RDP within 1 hour — the full chain | UNTESTED | Lab 03 |
| [100113](Rule-100113-High-Privilege-Logon.md) | 10 | 4624 | High-privilege account (SID -500) logged on | **TESTED** | Lab 04 |
| [100114](Rule-100114-Normal-User-Logon.md) | 5 | 4624 | Normal human user logged on | **TESTED** | Lab 04 |
| [100115](Rule-100115-Off-Hours-Logon.md) | 12 | 4624 | Any human account logged on outside business hours | **TESTED** | Lab 05 |
| [100116](Rule-100116-Off-Hours-Failed-Logon.md) | 8 | 4625 | Failed logon outside business hours — brute force | **TESTED** | Lab 05 |
| [100117](Rule-100117-Kerberos-TGT-Requested.md) | 3 | 4768 | Kerberos TGT ticket requested (AS-REP Roasting vector) | **TESTED** | Lab 08 |
| [100123](Rule-100123-DCSync-Replication.md) | 13 | 4662 | Non-DC Directory Service replication — DCSync attack | **TESTED** | Lab 13 |
| [100124](Rule-100124-Golden-Ticket-TGS-Request.md) | 11 | 4769 | Anomalous Kerberos service ticket request — Golden Ticket TGS | **TESTED** | Lab 13 |
| [100125](Rule-100125-Golden-Ticket-Administrative-Logon.md) | 12 | 4672 / 4624 | Administrative privilege assignment on network logon — Golden Ticket takeover | **TESTED** | Lab 13 |
| [100126](Rule-100126-PsExec-Lateral-Movement.md) | 12 | Sysmon 1 (184665) | Lateral Movement: PsExec execution detected on host via Sysmon Event 1 | **TESTED** | Lab 14 |
| [100127](Rule-100127-LSASS-Memory-Read-Detection.md) | 12 | Sysmon 10 | Critical: Memory read rights requested on LSASS (VM_READ) | **TESTED** | Lab 15 / 16 |
| [100128](Rule-100128-Taskmgr-LSASS-Whitelist.md) | 3 | Sysmon 10 | Whitelist: Task Manager routine diagnostic handle to LSASS | **TESTED** | Lab 15 |
| [100129](Rule-100129-LSASS-Memory-Dump-or-Kerberos-Ticket-File-Created.md) | 13 | Sysmon 11 | CRITICAL: LSASS Memory Dump or Kerberos Ticket File Written to Disk | **TESTED** | Lab 15 |

**Status meanings:**
- **TESTED** — the rule fired on a generated event in the lab, and the alert was observed in Threat Hunting. The file records when and what fired.
- **UNTESTED** — the rule is written from Wazuh's documented syntax and has not been run in the lab yet. The file carries a test plan, not test evidence. Do not treat it as verified detection.

**Count:** 25 custom rules — 18 tested, 7 untested.

---

## 🏛️ The 4-Tier LSASS Defense Hierarchy: Rules 100103, 100127, 100128, and 100129

Credential dumping from the Local Security Authority Subsystem Service (`lsass.exe`) is one of the most critical threats in Windows Active Directory environments. However, writing a single detection rule for LSASS access inevitably leads to either **massive alert fatigue** (hundreds of false positives from routine OS daemons) or **silent blindness** (missing stealthy memory dumpers).

In Lab 15, we engineered a production-grade **4-Tier Detection Hierarchy** deployed directly into `/var/ossec/etc/rules/local_rules.xml`.

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              THE 4-TIER LSASS DETECTION & SUPPRESSION PIPELINE                         │
├────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                        │
│  [ Incoming Telemetry Stream ]                                                                         │
│           │                                                                                            │
│           ├──► Sysmon Event ID 10 (ProcessAccess)                                                      │
│           │         │                                                                                  │
│           │         ▼                                                                                  │
│           │    [ Target: lsass.exe? ] ──► NO ──► Ignore                                                │
│           │         │ YES                                                                              │
│           │         ▼                                                                                  │
│           │    ┌──────────────────────────────────────────────────────────────┐                        │
│           │    │ TIER 1: Rule 100103 (Level 3 - Audit Base Collector)         │                        │
│           │    │ Captures all handles silently for forensic audit trail.      │                        │
│           │    └──────────────────────────────┬───────────────────────────────┘                        │
│           │                                   │                                                        │
│           │                                   ▼                                                        │
│           │                 [ GrantedAccess has VM_READ (0x10)? ]                                      │
│           │                 (0x1010 | 0x1410 | 0x1fffff | 0x0010)                                      │
│           │                        │                    │                                              │
│           │                       NO                   YES                                             │
│           │                        │                    │                                              │
│           │                        ▼                    ▼                                              │
│           │             [ Log Level 3 Only ]  ┌──────────────────────────────────────────────────┐     │
│           │             (VBoxService, svchost)│ TIER 2: Rule 100127 (Level 12 - Threat Detector) │     │
│           │             Zero Alert Fatigue    │ Weaponized memory reading handle intercepted.    │     │
│           │                                   └─────────────────┬────────────────────────────────┘     │
│           │                                                     │                                      │
│           │                                                     ▼                                      │
│           │                                      [ SourceImage == Taskmgr.exe? ]                       │
│           │                                             │               │                              │
│           │                                            YES              NO                             │
│           │                                             │               │                              │
│           │                                             ▼               ▼                              │
│           │                    ┌──────────────────────────────────┐  ┌───────────────────────────────┐ │
│           │                    │ TIER 3: Rule 100128 (Level 3)    │  │ CRITICAL LEVEL 12 ALARM FIRES │ │
│           │                    │ Whitelist suppression for Taskmgr│  │ rundll32, mimikatz, procdump  │ │
│           │                    └──────────────────────────────────┘  └───────────────────────────────┘ │
│           │                                                                                            │
│           └──► Sysmon Event ID 11 (FileCreate)                                                         │
│                     │                                                                                  │
│                     ▼                                                                                  │
│                [ TargetFilename matches (?i)lsass.*\.dmp|\.kirbi? ]                                    │
│                     │ YES                                                                              │
│                     ▼                                                                                  │
│                ┌─────────────────────────────────────────────────────────────────────────────┐         │
│                │ TIER 4: Rule 100129 (Level 13 - Maximum Critical Dump/Ticket File Detector) │         │
│                │ Secondary defense line: catches dump files or carved tickets written to disk│         │
│                └─────────────────────────────────────────────────────────────────────────────┘         │
│                                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Detailed Breakdown of Differences

| Feature | Tier 1: [Rule 100103](Rule-100103-LSASS-Access.md) | Tier 2: [Rule 100127](Rule-100127-LSASS-Memory-Read-Detection.md) | Tier 3: [Rule 100128](Rule-100128-Taskmgr-LSASS-Whitelist.md) | Tier 4: [Rule 100129](Rule-100129-LSASS-Memory-Dump-or-Kerberos-Ticket-File-Created.md) |
|---|---|---|---|---|
| **Severity Level** | **Level 3** (Informational Audit) | **Level 12** (Critical High Alarm) | **Level 3** (Whitelist Suppression) | **Level 13** (Maximum Critical Alarm) |
| **Telemetry Event** | Sysmon Event ID **10** (`ProcessAccess`) | Sysmon Event ID **10** (`ProcessAccess`) | Sysmon Event ID **10** (`ProcessAccess`) | Sysmon Event ID **11** (`FileCreate`) |
| **Monitored Field** | `win.eventdata.targetImage` | `win.eventdata.grantedAccess` | `win.eventdata.sourceImage` | `win.eventdata.targetFilename` |
| **Filter Criteria** | Ends with `lsass.exe` | `0x1010 \| 0x1410 \| 0x1fffff \| 0x0010` | `Taskmgr\.exe$` | `(?i)lsass.*\.dmp\|\.kirbi` (PCRE2) |
| **Operational Role** | Base telemetry ingestion root | Weaponized memory-read detector | Administrative false-positive suppressor | File system artifact safety net |
| **Parent Rule** | Core `windows` group | `<if_sid>100103</if_sid>` | `<if_sid>100127</if_sid>` | Core `windows` group |
| **SOC Action** | Silent indexing, timeline hunting | Immediate host isolation & triage | Silent indexing, routine admin log | Immediate credential revocation & quarantine |

---

### When Does Each Rule Fire? (Operational Matrix)

| Operational Scenario | Calling Process / Action | Win32 Bitmask / Filename | Matched Rule | Resulting Severity & Action |
|---|---|---|---|---|
| **Hypervisor Polling Loop** | `VBoxService.exe` polls session state every 15s | `0x1400` (`QUERY_INFO`) | **Rule 100103** | **Level 3 (Silent Audit).** Zero alert noise. |
| **System Service Status Check** | `svchost.exe` queries process status | `0x1000` (`QUERY_LIMITED`) | **Rule 100103** | **Level 3 (Silent Audit).** Zero alert noise. |
| **Administrator Server Health Check** | Admin opens `Taskmgr.exe` to inspect CPU/RAM | `0x1fffff` (`ALL_ACCESS`) | **Rule 100128** | **Level 3 (Suppressed).** Matches 100103 $\rightarrow$ passes to 100127 $\rightarrow$ demoted by 100128. |
| **Living-off-the-Land Memory Dump** | `rundll32.exe comsvcs.dll, MiniDump` | `0x1fffff` / `0x1410` | **Rule 100127** | **Level 12 (Critical Alert).** Immediate alert on SOC dashboard. |
| **Third-Party Credential Dumper** | `procdump.exe -ma lsass.exe` / `mimikatz` | `0x1010` / `0x0010` | **Rule 100127** | **Level 12 (Critical Alert).** Immediate alert on SOC dashboard. |
| **Memory Dump Written to Disk** | Dump file written to `C:\Users\Public\lsass.dmp` | `lsass.dmp` | **Rule 100129** | **Level 13 (Max Critical).** Immediate file creation alert. |
| **Harvested Kerberos Tickets Dropped** | Mimikatz `sekurlsa::tickets /export` | `[0;12a45]-2-0-40e10000.kirbi` | **Rule 100129** | **Level 13 (Max Critical).** Immediate ticket carving alert. |

---

## Shadowing map

Shadowing is the single most important behaviour in this ruleset: when a custom rule matches an event, the built-in rule that would also have matched **stays silent**. That is how Wazuh rule matching works — it is not a bug — but you have to know it is happening, or you will misread your coverage. Every shadowing claim below was proven by a live experiment, not assumed.

| Custom rule | Shadows (stays silent on match) | Proven | How it was proven |
|---|---|---|---|
| **100105** | Built-in **60141** (4728, any group) | Oct 17, 2026 | Removed the custom rules → 60141 fired. Restored them → 60141 silent, only 100105 fired. |
| **100113 / 100114** | Built-in **60106** (4624, human logons) | Nov 8, 2026 | `rule.id: 60106 AND data.win.eventdata.ipAddress: 192.168.100.27` returned nothing — 60106 silent on human logons. Machine logons still fire 60106 (coverage preserved). |
| **100113 / 100114** | Built-in **92653** (RDP logon, type 10) | Nov 9, 2026 | 92653 last fired Nov 8 18:08, before the custom rules loaded. After loading, every RDP logon fired 100113/100114 and 92653 went silent. |
| **100116** | Built-in **60122** (4625, off-hours only) | Nov 9, 2026 | After 100116 loaded, every failed logon fired 100116 only — 60122 showed just 4 old hits, latest 01:16:48. During on-hours 100116 does not match, so 60122 fires again (proven by the time-flip test). |
| **100125** | Built-in **67020** (EventChannel 4672 privilege assignment) | Nov 17, 2026 | 67020 fires at Level 3 for baseline privilege assignments. Rule 100125 shadows 67020 when `normaluser01` receives special privileges via injected PAC, escalating the incident to Level 12. |
| **100126** | Built-in **184665** (Sysmon Event 1 Process Creation) | Nov 19, 2026 | 184665 fires at Level 3 for generic Sysmon process creation. Rule 100126 shadows 184665 when `PSEXESVC.exe` or dropped root service binaries execute, escalating the incident to Level 12. |
| **100127** | Parent **100103** (Base LSASS Handle Collector) | Nov 23, 2026 | Rule 100103 logs handles at Level 3. Rule 100127 shadows 100103 whenever memory-read permissions (`0x1010`, `0x1410`, `0x1fffff`, `0x0010`) are requested, escalating to Level 12. |
| **100128** | Parent **100127** (Weaponized LSASS Memory Read) | Nov 23, 2026 | Rule 100127 alerts at Level 12 for handles with `0x1fffff`. Rule 100128 shadows 100127 when `sourceImage` is `Taskmgr.exe`, demoting the diagnostic event back to Level 3. |
| **100129** | Built-in Sysmon Event 11 rules (`FileCreate`) | Nov 23, 2026 | Built-in Sysmon rules index file creations at Level 3. Rule 100129 matches filenames matching `lsass.*\.dmp` or `\.kirbi`, escalating to Level 13. |

### Dependency chains — and the one that is broken

| Rule | Depends on | Status |
|---|---|---|
| **100111** | **100105** (parent) + **60109** (matched) | Sound. 100111 chains on 100105, not on 60141, precisely because 60141 is shadowed on privileged 4728s and would never fire. |
| **100112** | **92653** (parent) + **100111** (matched) | **BROKEN — redesign required.** 100112 chains on `<if_sid>92653</if_sid>`, but 92653 is now shadowed by 100113/100114 and no longer fires on type-10 logons. The RDP link of the chain can never trigger. The fix is to re-parent 100112 on 100113/100114 (or on a 4624 rule that actually fires) before the Lab 03 test. Do not test 100112 as written and expect it to fire. |
| **100116** | **60122** (parent) | Sound. 60122 still fires on-hours (when 100116 does not match), so the parent is alive — 100116 only suppresses it during off-hours. |
| **100127** | **100103** (parent) | Sound. Inherits from base LSASS handle rule 100103; triggers on weaponized `GrantedAccess` bitmasks. |
| **100128** | **100127** (parent) | Sound. Inherits from threat rule 100127; intercepts `Taskmgr.exe` and suppresses false alarms to Level 3. |

### The rule to remember

**A correlation chain is only as strong as its weakest parent.** Before chaining on a rule, check that the parent actually fires in the live system. If the parent is shadowed, the child is blind — and the blindness is silent, because a rule that never fires produces no alert and no error.

## How to read a rule file

Every file in this folder follows the same shape:

1. **Rule** — the exact XML, as deployed (or as written, for untested rules).
2. **What it detects** — the event and the dangerous subset it isolates.
3. **Purpose** — why this rule exists, in one paragraph.
4. **How it works** — each field and condition, in plain English, line by line.
5. **Shadowing and dependencies** — what it suppresses, what it depends on, what breaks if a parent disappears.
6. **Test evidence / test plan** — what fired in the lab (with dates), or the exact test to run if it has not fired yet.
7. **Find it in Wazuh** — the copy-paste DQL query for its alerts.
8. **MITRE ATT&CK** — the technique ID and what it means.

## Deploying these rules

Rules ship to the manager as `local_rules.xml`. The deploy sequence (Kali):

```bash
docker cp local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

Three standing rules from the lab: **`chown wazuh:wazuh` after every `docker cp`** (ownership, not XML, was the Nov 8 outage — `docker cp` leaves the file owned by uid 1000 and `wazuh-db` cannot read it); **validate with `wazuh-analysisd -t` before restarting** (it catches a deleted `<group>` wrapper while the old rules are still running); **edit single lines with `sed`, not `nano`** (a `nano` edit once deleted the `<group>` wrapper and broke the whole file). Always back the file up first.

---

*Part of [Wazuh Home SOC Lab](../README.md). The lab-by-lab build stories live in [03-Custom-Detection-Rules](../03-Custom-Detection-Rules/).*
