# Account Management & Logon Detection Labs

*Part of the [Core Detection Labs](../README.md) — an Active Directory auditing and Windows Security Event Log detection series.*

---

## Overview

This section contains the foundational Windows Security Event Log detection engineering labs, focusing on **Account Management (Audit Policy Subcategory)**, **Logon/Logoff Auditing**, **Privilege Escalation**, and **SOC Incident Triage**.

Every lab follows a full purple-team loop: **Attack Execution $\rightarrow$ Event Generation $\rightarrow$ Wazuh Telemetry Ingestion $\rightarrow$ Rule Alerting $\rightarrow$ SOC Playbook Triage**.

---

## Lab Index

| # | Lab | What It Proves | Event IDs |
|---|---|---|---|
| **01** | [RDP Logon Detection](01-RDP-Logon-Detection-4624-4625/) | Remote interactive (Logon Type 10) vs network (Logon Type 3) logons landing in SIEM — reading 4624/4625 like an analyst | 4624, 4625 |
| **02** | [Privilege Escalation Detection](02-Privilege-Escalation-Detection-4728-4729/) | The classic attack pattern: account added to a privileged group (`Domain Admins`), then removed — the Event 4728 moment | 4728, 4729 |
| **03** | [Account Lifecycle Auditing](03-Account-Lifecycle-Auditing-4720-to-4740/) | Full account lifecycle (create $\rightarrow$ disable $\rightarrow$ enable $\rightarrow$ delete) plus a real lockout and Kerberos logging blind spots | 4720, 4725, 4722, 4726, 4740, 4767 |
| **04** | [Brute-Force Mini-Incident: Triage](04-Brute-Force-Mini-Incident-Triage/) | Failures $\rightarrow$ lockout $\rightarrow$ unlock $\rightarrow$ success, worked end-to-end as a SOC triage case with written analyst verdict | 4625, 4740, 4767, 4624 |
| **05** | [Chained Attack: One Incident, Five Alerts](05-Chained-Attack-One-Incident-Five-Alerts/) | One attacker story, five alerts — backdoor account $\rightarrow$ privileged group $\rightarrow$ RDP logon $\rightarrow$ process $\rightarrow$ log cleared | 4720, 4728, 4624, 4688, 1102 |
| **06** | [Rogue Admin: Purple-Team Story](06-Rogue-Admin-Purple-Team/) | Lab 05 retold as one attack story, then broken step-by-step: evasion techniques, what still catches it, and breaking detection | 4720, 4728, 4624, 4688, 1102 |
| **07** | [Alert Triage SOP](07-Alert-Triage-SOP/) | What the analyst does when an alert arrives — one triage flow, per-alert playbooks, severity ranking, and escalation criteria | 4720, 4728, 4624, 4688, 1102, 4738 |
