# Event 4726 — User account deleted

*Part of the [Account Management lab](../README.md) — 27 Windows events mapped to Wazuh, interview-prep edition.*

---
**What it means:** The account object was permanently deleted from AD.

**Why a SOC analyst cares:** *"Deletion is forever — and it's how attackers remove evidence. A deletion in odd hours, or of an account tied to an incident I'm already investigating, is a red flag. Legitimate deletions follow HR offboarding during business hours. I always check: who deleted it, and what did that account do in its last 24 hours?"*

**Wazuh:** rule **60111**, level **8** — verdict: **covered**.

**Generate:** `Remove-ADUser -Identity "testuser02" -Confirm:$false`

**Cleanup:** the deletion *is* the cleanup; to undo it, recreate the account (fires a new 4720).

![Remove-ADUser command](images/4726-aduc-delete-confirmation.png)

---
![Threat Hunting alert, rule 60111](images/4726-list-60111-disabled-or-deleted.png)

---

## Threat Hunting in Wazuh

Threat Hunting uses DQL. Paste these into the search bar (Events tab) over the time window of the lab. Threat Hunting shows the **alerts** index only — if an event fired no rule, it is invisible here; check the archives index or `Get-WinEvent` on the DC instead.

**All of them:**
```
data.win.system.eventID: 4726
```

**Just one account:**
```
data.win.system.eventID: 4726 AND data.win.eventdata.targetUserName: testuser02
```

**Who did it:**
```
data.win.system.eventID: 4726 AND data.win.eventdata.subjectUserName: administrator
```

**By rule:**
```
rule.id: 60111 AND data.win.system.eventID: 4726
```

**Human accounts only** (drops computer accounts ending in `$` and SYSTEM noise):
```
data.win.system.eventID: 4726 AND NOT data.win.eventdata.targetUserName: *$ AND NOT data.win.eventdata.targetUserName: SYSTEM
```
