# Event 4756 — Member added to security-enabled universal group

*Part of the [Account Management lab](../README.md) — 27 Windows events mapped to Wazuh, interview-prep edition.*

---
**What it means:** Someone was added to a universal security group — the 4728 moment, but forest-wide.

**Why a SOC analyst cares:** *"This is 4728 with a bigger blast radius. Membership in a privileged universal group can mean privileges in every domain in the forest — and universal membership replicates through the Global Catalog, so it spreads fast. If an attacker lands here, containment gets much harder. In a multi-domain environment, this is the highest-priority group-membership event I watch."*

**Wazuh:** rule **60151**, level **5** — verdict: **covered**.

**Generate:**
```powershell
Add-ADGroupMember -Identity "U-TestUniversal" -Members "testuser01"
```

**Cleanup:** `Remove-ADGroupMember -Identity "U-TestUniversal" -Members "testuser01" -Confirm:$false` (fires 4757).

![Add-ADGroupMember to universal group](images/4756-powershell-add-member-universal.png)
![Threat Hunting alert, rule 60151](images/4756-message-member-added.png)
