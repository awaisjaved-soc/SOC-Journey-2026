# Event 4740 — Account locked out

*Part of the [Account Management lab](../README.md) — 27 Windows events mapped to Wazuh, interview-prep edition.*

---
**What it means:** An account was automatically locked after too many failed logons.

**Why a SOC analyst cares:** *"4740 is the brute-force alarm bell. One lockout is usually a user fat-fingering their password. But lockouts across many accounts from one source IP is password spraying — and a lockout followed by a successful logon from an unusual IP is the nightmare scenario: they guessed right. I always check what happened right after the lockout."*

**Wazuh:** rule **60115**, level **9** — verdict: **covered**. The highest level in this lab's account events, and it earns it.

**Generate:** set an account lockout threshold via Group Policy (5 attempts in this lab), then fail logons 5 times as the user.

**Cleanup:** `Unlock-ADAccount -Identity "testuser02"` (fires 4767).

**Watch out:** without a lockout-threshold policy, **4740 can never fire** — the lab initially had no threshold, so this event was untestable until the policy was added. A detection that can't fire is the same as no detection.

![lockout threshold GPO setting](images/4740-logon-screen-account-locked-out.png)

---
![Threat Hunting alert, rule 60115, level 9](images/4740-threat-hunting-search-60115.png)

---
![failed logons leading to the lockout](images/4740-alert-detail-smitchell-locked.png)

---

## Threat Hunting in Wazuh

Threat Hunting uses DQL. Paste these into the search bar (Events tab) over the time window of the lab. Threat Hunting shows the **alerts** index only — if an event fired no rule, it is invisible here; check the archives index or `Get-WinEvent` on the DC instead.

**All of them:**
```
data.win.system.eventID: 4740
```

**Just one account:**
```
data.win.system.eventID: 4740 AND data.win.eventdata.targetUserName: testuser02
```

**Who did it:**
```
data.win.system.eventID: 4740 AND data.win.eventdata.subjectUserName: administrator
```

**By rule:**
```
rule.id: 60115 AND data.win.system.eventID: 4740
```

**Human accounts only** (drops computer accounts ending in `$` and SYSTEM noise):
```
data.win.system.eventID: 4740 AND NOT data.win.eventdata.targetUserName: *$ AND NOT data.win.eventdata.targetUserName: SYSTEM
```

Never read a lockout alone — pair it with the 4767 unlock that follows it and the 4625 failures that came before it. Lockouts across many accounts from one source IP is password spraying.
