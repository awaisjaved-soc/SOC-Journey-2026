# Event 4729 — Member removed from security-enabled global group

*Part of the [Account Management lab](../README.md) — 27 Windows events mapped to Wazuh, interview-prep edition.*

---
**What it means:** Someone was removed from a global security group — a badge taken away.

**Why a SOC analyst cares:** *"Removal cuts access — normal for role changes and offboarding. But there's a darker read: an attacker removing their backdoor account from a privileged group after they're done, cleaning up the 4728 that gave them away. I check removals against the additions: does every 4729 have a matching, explainable 4728 somewhere in history?"*

**Wazuh:** rule **60142**, level **5** — verdict: **covered**.

**Generate:**
```powershell
Remove-ADGroupMember -Identity "GG-Sales" -Members "testuser01" -Confirm:$false
```

**Cleanup:** re-add the member (`Add-ADGroupMember`).

![Remove-ADGroupMember command](images/4729-powershell-remove-member-history.png)

---
![Threat Hunting alert, rule 60142](images/4729-threat-hunting-search-60142.png)

---

## Threat Hunting in Wazuh

Threat Hunting uses DQL. Paste these into the search bar (Events tab) over the time window of the lab. Threat Hunting shows the **alerts** index only — if an event fired no rule, it is invisible here; check the archives index or `Get-WinEvent` on the DC instead.

**All of them:**
```
data.win.system.eventID: 4729
```

**One group:**
```
data.win.system.eventID: 4729 AND data.win.eventdata.targetUserName: GG-Sales
```

**One member:**
```
data.win.system.eventID: 4729 AND data.win.eventdata.memberName: *testuser01*
```

**Who did it:**
```
data.win.system.eventID: 4729 AND data.win.eventdata.subjectUserName: administrator
```

**By rule:**
```
rule.id: 60142 AND data.win.system.eventID: 4729
```

**Human members only** (drops computer accounts and nested groups ending in `$`):
```
data.win.system.eventID: 4729 AND NOT data.win.eventdata.memberName: *$
```
