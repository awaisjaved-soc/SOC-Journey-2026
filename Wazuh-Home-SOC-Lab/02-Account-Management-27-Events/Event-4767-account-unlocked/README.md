# Event 4767 — Account unlocked

*Part of the [Account Management lab](../README.md) — 27 Windows events mapped to Wazuh, interview-prep edition.*

---
**What it means:** An administrator unlocked a locked account.

**Why a SOC analyst cares:** *"The all-clear after a lockout — or the attacker unlocking their own backdoor account. I never read 4767 alone; I pair it with the 4740 that came before it. Was there a brute-force pattern? And critically: did anyone log on successfully after the unlock, and from where?"*

**Wazuh:** rule **60133**, level **5** — verdict: **covered**.

**Generate:** `Unlock-ADAccount -Identity "testuser02"`

**Cleanup:** none needed.

![Unlock-ADAccount command](images/4767-alert-detail-testuser01-unlocked.png)
![Threat Hunting alert, rule 60133](images/4767-threat-hunting-list-60133.png)
