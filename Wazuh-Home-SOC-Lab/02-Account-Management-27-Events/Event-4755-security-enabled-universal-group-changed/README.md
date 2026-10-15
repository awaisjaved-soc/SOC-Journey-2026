# Event 4755 — Security-enabled universal group changed

*Part of the [Account Management lab](../README.md) — 27 Windows events mapped to Wazuh, interview-prep edition.*

---
**What it means:** A universal group's attributes were modified.

**Why a SOC analyst cares:** *"Same triage as 4737 — someone edited the group rather than its membership — with the forest-wide scope in mind. A quiet edit to a forest-wide badge is exactly the kind of thing that doesn't alarm anyone and should."*

**Wazuh:** rule **60150**, level **5** — verdict: **covered**.

**Generate:**
```powershell
Set-ADGroup -Identity "U-TestUniversal" -Description "Test universal group"
```

**Cleanup:** revert the attribute.

![Set-ADGroup on universal group](images/4755-detail-universal-group-changed.png)
![Threat Hunting alert, rule 60150](images/4755-list-60150-group-changed.png)
