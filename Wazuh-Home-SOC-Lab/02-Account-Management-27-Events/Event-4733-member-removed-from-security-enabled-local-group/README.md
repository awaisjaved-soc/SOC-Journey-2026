# Event 4733 — Member removed from security-enabled local group

*Part of the [Account Management lab](../README.md) — 27 Windows events mapped to Wazuh, interview-prep edition.*

---
**What it means:** Someone's key to a *specific* resource was revoked.

**Why a SOC analyst cares:** *"Their access to that one door is gone. Usually a role change — but timing matters. If the removal happens right after sensitive data was accessed from that resource, it can be an attacker covering their tracks: take what you need, then return the key."*

**Wazuh:** rule **60145**, level **5** — verdict: **covered**.

**Generate:**
```powershell
Remove-ADGroupMember -Identity "DL-SecretData-Read" -Members "GG-Sales" -Confirm:$false
```

**Cleanup:** re-add the member (fires 4732).

![Remove-ADGroupMember from DL group](screenshots/4733-powershell-remove-member-history.png)
*No screenshot captured for this step — Threat Hunting alert, rule 60145.*
