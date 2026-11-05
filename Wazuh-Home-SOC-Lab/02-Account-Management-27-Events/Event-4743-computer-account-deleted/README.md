# Event 4743 — Computer account deleted

*Part of the [Account Management lab](../README.md) — 27 Windows events mapped to Wazuh, interview-prep edition.*

---
**What it means:** A computer account was deleted — that machine's domain identity no longer exists.

**Why a SOC analyst cares:** *"The machine can't authenticate anymore. Usually decommissioning. But paired with a recent 4741 by an unusual user, it reads differently: create a ghost account, use it, delete it. I check the account's lifetime — created and deleted within hours is not decommissioning."*

**Wazuh:** rule **60121**, level **5** — verdict: **covered**.

**Generate:** `Remove-ADComputer -Identity "TEST-PC01" -Confirm:$false`

**Cleanup:** recreate the account if the machine still needs domain membership (fires a new 4741).

![Remove-ADComputer command](images/4743-message-computer-account-deleted.png)

---
![Threat Hunting alert, rule 60121](images/4743-detail-test-pc01-deleted.png)

---

## Threat Hunting in Wazuh

Threat Hunting uses DQL. Paste these into the search bar (Events tab) over the time window of the lab. Threat Hunting shows the **alerts** index only — if an event fired no rule, it is invisible here; check the archives index or `Get-WinEvent` on the DC instead.

**All of them:**
```
data.win.system.eventID: 4743
```

**One computer:**
```
data.win.system.eventID: 4743 AND data.win.eventdata.targetUserName: TEST-PC01
```

**Who did it:**
```
data.win.system.eventID: 4743 AND data.win.eventdata.subjectUserName: administrator
```

**By rule:**
```
rule.id: 60121 AND data.win.system.eventID: 4743
```

Note: the target here is a computer account, so it ends in `$` — do not use the human-only `NOT *$` filter on this event.
