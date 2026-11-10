# Phase 2 — Logon & Authentication: Recall + Wazuh Mapping Sheet

**Category:** Logon & Authentication Events (14 events)
**Goal of this phase:** prove you know them cold, then map every one to Wazuh (built-in rule or gap).
**How to use:** read your READMEs first. Then do Part A from memory — no peeking. Then Part B in your Wazuh dashboard.

---

## PART A — RECALL QUIZ (from memory, then verify)

### All 14 — say the meaning AND why a SOC analyst cares

- [ ] **4624** — Meaning: successful logon / SOC cares because: every logon is a door opening — who logged on, from where, what type; a privileged account logging on at 3am from an unknown IP is the first sign of a breach
- [ ] **4625** — Meaning: failed logon / SOC cares because: one failure is a typo, many failures is a brute-force attack in progress — a sudden burst against one account means someone is guessing passwords right now
- [ ] **4634** — Meaning: logoff, session ended / SOC cares because: pairs with 4624 to show how long a session lasted — a session that ends seconds after logon, or never ends, tells you what happened in between
- [ ] **4647** — Meaning: user-initiated logoff / SOC cares because: the user chose to log off — different from a session dying on its own; if a user logs off right after a privileged action, check what they did in between
- [ ] **4648** — Meaning: logon with explicit credentials, RunAs or a second account / SOC cares because: someone used a second set of credentials — legit for admins, but an attacker uses RunAs to step up to a privileged account without logging off
- [ ] **4672** — Meaning: special privileges assigned to a new logon / SOC cares because: this is the admin-logon flag — when a privileged account logs on, this fires; an attacker logging on as admin lights this up, so watch it
- [ ] **4768** — Meaning: Kerberos TGT requested / SOC cares because: the first step of Kerberos auth — a TGT request from an unusual host or for a privileged account is the start of ticket-based attacks
- [ ] **4769** — Meaning: Kerberos service ticket requested / SOC cares because: a ticket to a specific service — bulk 4769s to many services is Kerberoasting or lateral movement in progress
- [ ] **4771** — Meaning: Kerberos pre-authentication failed / SOC cares because: wrong password against Kerberos — repeated 4771s mean password guessing, and the account still locks out even when the events are invisible without the right audit subcategory
- [ ] **4776** — Meaning: credential validation, NTLM / SOC cares because: NTLM auth happened — NTLM is weaker than Kerberos, so a spike in 4776s can mean pass-the-hash or legacy auth abuse
- [ ] **4778** — Meaning: session reconnected, RDP / SOC cares because: someone reconnected to a disconnected RDP session — an attacker reconnecting to a victim's session takes over their desktop without a fresh logon
- [ ] **4779** — Meaning: session disconnected, RDP / SOC cares because: the RDP session was left hanging — a disconnected session is still live on the server and can be reconnected by anyone who reaches it
- [ ] **4800** — Meaning: workstation locked / SOC cares because: the user locked their screen — a lock right after a sensitive action can mean the user walked away mid-task, or someone else locked it
- [ ] **4801** — Meaning: workstation unlocked / SOC cares because: someone unlocked the workstation — if the unlock does not match the user's normal pattern, check who sat at that keyboard

Scoring: 14/14 cold = solid. Anything you blanked on → re-read that README, then say it again out loud. That's the gap closing.

### All 14 events in order — one-line meaning each (memorize these)

- [ ] 4624 — Successful logon
- [ ] 4625 — Failed logon
- [ ] 4634 — Logoff (session ended)
- [ ] 4647 — User-initiated logoff
- [ ] 4648 — Logon with explicit credentials (RunAs)
- [ ] 4672 — Special privileges assigned to new logon
- [ ] 4768 — Kerberos TGT requested
- [ ] 4769 — Kerberos service ticket requested
- [ ] 4771 — Kerberos pre-authentication failed
- [ ] 4776 — Credential validation (NTLM)
- [ ] 4778 — Session reconnected (RDP)
- [ ] 4779 — Session disconnected (RDP)
- [ ] 4800 — Workstation locked
- [ ] 4801 — Workstation unlocked

---

## PART B — WAZUH MAPPING TABLE (fill in your dashboard)

**How to check each event (why: this is exactly how you'd validate coverage on shift):**

1. Dashboard → **Management → Rules** → search the event ID (e.g. `4624`). Note the rule ID and level.
2. Generate the event in your lab (use your portfolio's PowerShell methods).
3. Watch **Threat Hunting** — does an alert fire? At what level? Does the rule name match what you expected?
4. Verdict: **covered** (good as-is), **needs tuning** (fires but noisy/weak), or **GAP** (nothing fires).

**Status of this sheet:** 5 of 14 events are now mapped from real lab alerts (4624, 4625, 4768, 4769, 4771). Every other row says **verify in lab** — generate the event, read the rule ID off the fired alert, fill the row. Never copy a rule ID from the Rules page alone; the alert is the proof. Two notes before you start: 4771 only appears if the **Kerberos Authentication Service** audit subcategory is enabled (same lesson as 4688 needing Process Creation), and 4624 fires 60106 on *every* logon — filter by account and type or you will drown.

| Event | Meaning | Wazuh rule ID | Level | Verdict |
| --- | --- | --- | --- | --- |
| 4624 | Successful logon | 60118 + 60106 | 3 | needs tuning |
| 4625 | Failed logon | 60122 | 5 | to verify (level) |
| 4634 | Logoff (session ended) | verify in lab | — | to verify |
| 4647 | User-initiated logoff | verify in lab | — | to verify |
| 4648 | Logon with explicit credentials (RunAs) | verify in lab | — | to verify |
| 4672 | Special privileges assigned to new logon | verify in lab | — | to verify |
| 4768 | Kerberos TGT requested | 100117 (custom) | 3 | covered |
| 4769 | Kerberos service ticket requested | 60106 / 100102 | 3 / 10 | covered |
| 4771 | Kerberos pre-authentication failed | 60104 | 5 | covered |
| 4776 | Credential validation (NTLM) | verify in lab | — | to verify |
| 4778 | Session reconnected (RDP) | verify in lab | — | to verify |
| 4779 | Session disconnected (RDP) | verify in lab | — | to verify |
| 4800 | Workstation locked | verify in lab | — | to verify |
| 4801 | Workstation unlocked | verify in lab | — | to verify |

## PHASE 2 DONE = all of this

- [ ] Part A: all 14 events recalled cold (meaning + why a SOC analyst cares), all 14 meanings memorized in order
- [ ] Part B: all 14 rows filled — every event has a rule ID + level, or is marked GAP
- [ ] One-line verdict per event: covered / needs tuning / gap

When this sheet is full, Phase 2 is done and we move to Sysmon. Bring me the sheet (or just tell me the GAP rows) and we start the next category.