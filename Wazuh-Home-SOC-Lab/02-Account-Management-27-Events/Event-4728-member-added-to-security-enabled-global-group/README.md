# Event 4728 — Member added to security-enabled global group

*Part of the [Account Management lab](../README.md) — 27 Windows events mapped to Wazuh, interview-prep edition.*

---
**What it means:** Someone was added to a global security group. **This is the moment permission is granted** — the 4728 event *is* the handover of power.

**Why a SOC analyst cares:** *"This is the single most important event in the category. 4728 is the exact instant someone is handed a privilege — group membership is when access is granted, not when it's used. An attacker adding a low-privilege account to Domain Admins is the textbook privilege-escalation pattern. My triage is always the same four questions: who was added, to which group, by whom, and was there a change ticket? If any answer is missing, it's an incident until proven otherwise."*

**Wazuh:** rule **60141**, level **5** — verdict: **covered**. (The lab also has a custom rule, **100105**, that fires louder specifically on *privileged*-group additions — built-in coverage is good, targeted coverage is better.)

**Generate:**
```powershell
Add-ADGroupMember -Identity "GG-Sales" -Members "testuser01"
```

**Cleanup:** `Remove-ADGroupMember -Identity "GG-Sales" -Members "testuser01" -Confirm:$false` (fires 4729).

**Watch out:** verify group scope in the alert — 4728 (global), 4732 (local), and 4756 (universal) are three different events with three different blast radii, and they fire three different Wazuh rules.

![Add-ADGroupMember command](images/4728-alert-detail-eventid-4728.png)

---
![Threat Hunting alert, rule 60141 firing](images/4728-threat-hunting-search-60141.png)

---
![alert detail: who added whom to what](images/4728-detail-testuser01-gg-sales.png)

---

## Threat Hunting in Wazuh

Threat Hunting uses DQL. Paste these into the search bar (Events tab) over the time window of the lab. Threat Hunting shows the **alerts** index only — if an event fired no rule, it is invisible here; check the archives index or `Get-WinEvent` on the DC instead.

**All of them:**
```
data.win.system.eventID: 4728
```

**One group:**
```
data.win.system.eventID: 4728 AND data.win.eventdata.targetUserName: GG-Sales
```

**One member:**
```
data.win.system.eventID: 4728 AND data.win.eventdata.memberName: *testuser01*
```

**Who did it:**
```
data.win.system.eventID: 4728 AND data.win.eventdata.subjectUserName: administrator
```

**By rule:**
```
rule.id: 60141 AND data.win.system.eventID: 4728
```

**Human members only** (drops computer accounts and nested groups ending in `$`):
```
data.win.system.eventID: 4728 AND NOT data.win.eventdata.memberName: *$
```

**The custom rule (privileged groups only):**
```
rule.id: 100105
```

The custom rule 100105 fires louder (level 10) specifically on privileged-group additions. With the custom rules loaded, 60141 stays silent on privileged adds (shadowing) — if 60141 fires on a privileged add, the custom rule is not loaded. See Lab 01 in 03-Custom-Detection-Rules.
