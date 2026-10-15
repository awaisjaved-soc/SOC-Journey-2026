# Event 4725 — User account disabled

*Part of the [Account Management lab](../README.md) — 27 Windows events mapped to Wazuh, interview-prep edition.*

---
**What it means:** An account was disabled — it can't log on, but the object (and its history) is kept.

**Why a SOC analyst cares:** *"Disabling is the reversible off-switch: leavers, suspensions, incident response. If I see an account disabled and then re-enabled an hour later, I want to know why — that pattern can be an attacker toggling access, or an admin who changed their mind. Either way it gets a question."*

**Wazuh:** rule **60111**, level **8** — verdict: **covered**.

**Generate:** `Disable-ADAccount -Identity "testuser02"`

**Cleanup:** `Enable-ADAccount -Identity "testuser02"`

![Disable-ADAccount command](images/4725-alert-detail-rpatel-disabled.png)
![Threat Hunting alert, rule 60111](images/4725-list-60111.png)
