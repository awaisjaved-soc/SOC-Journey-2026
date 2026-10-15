# Event 4757 — Member removed from security-enabled universal group

*Part of the [Account Management lab](../README.md) — 27 Windows events mapped to Wazuh, interview-prep edition.*

---
**What it means:** Someone was removed from a universal security group.

**Why a SOC analyst cares:** *"Access revoked across the forest — or cleanup after the fact. Same read as 4729 and 4733: legitimate for role changes, suspicious when it follows the activity it might be hiding."*

**Wazuh:** rule **60152**, level **5** — verdict: **covered**.

**Generate:**
```powershell
Remove-ADGroupMember -Identity "U-TestUniversal" -Members "testuser01" -Confirm:$false
```

**Cleanup:** re-add the member.

![Remove-ADGroupMember from universal group](images/4757-powershell-remove-member.png)
![Threat Hunting alert, rule 60152](images/4757-list-60152-member-removed.png)
