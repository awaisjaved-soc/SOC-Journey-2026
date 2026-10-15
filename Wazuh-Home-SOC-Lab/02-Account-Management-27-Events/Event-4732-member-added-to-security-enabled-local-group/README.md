# Event 4732 — Member added to security-enabled local group

*Part of the [Account Management lab](../README.md) — 27 Windows events mapped to Wazuh, interview-prep edition.*

---
**What it means:** A member was added to a domain local security group — someone just got a key cut for a specific door.

**Why a SOC analyst cares:** *"This is the moment access is granted to a resource. In this lab it was the GG-Sales badge being nested into DL-SecretData-Read — the key being cut. My questions on shift: who got access to what, who approved it, and does a business need justify it? Attackers love this event because it's quieter than creating accounts — they just collect keys to doors."*

**Wazuh:** rule **(verify from fired alert)** — verdict: **covered**.

**Generate:**
```powershell
Add-ADGroupMember -Identity "DL-SecretData-Read" -Members "GG-Sales"
```

**Cleanup:** `Remove-ADGroupMember -Identity "DL-SecretData-Read" -Members "GG-Sales" -Confirm:$false`

![Add-ADGroupMember to DL group](screenshots/4732-powershell-add-member-history.png)
*No fired-alert screenshot was captured for 4732 — the generation command above is the lab evidence. Read the rule ID off your own fired alert to confirm.*
