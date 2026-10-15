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
![Threat Hunting alert, rule 60142](images/4729-threat-hunting-search-60142.png)
