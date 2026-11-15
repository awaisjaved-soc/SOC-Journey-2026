# Core Detection Labs

Welcome to the **Core Detection Labs** series. This section represents a comprehensive hands-on detection engineering curriculum executed on a live Windows Server 2022 Active Directory Domain Controller (`WIN-SOCLAB`) and monitored by **Wazuh SIEM 4.14.5** deployed in Docker on Kali Linux (`192.168.100.50`).

The curriculum is structured into **two primary pillars**:

```text
01-Core-Detection-Labs/
├── 01-Account-Management-Event-Detection-Labs/      # Foundational Active Directory & Logon Auditing
│   ├── 01-RDP-Logon-Detection-4624-4625/
│   ├── 02-Privilege-Escalation-Detection-4728-4729/
│   ├── 03-Account-Lifecycle-Auditing-4720-to-4740/
│   ├── 04-Brute-Force-Mini-Incident-Triage/
│   ├── 05-Chained-Attack-One-Incident-Five-Alerts/
│   ├── 06-Rogue-Admin-Purple-Team/
│   └── 07-Alert-Triage-SOP/
│
└── 02-Kerberos-Attacks-and-Defense-Labs/           # Advanced Kerberos Cryptography & Lateral Movement
    ├── 08-Kerberos-Authentication-and-AS-REP-Roasting/
    ├── 09-Kerberos-Service-Ticket-and-Kerberoasting/
    ├── 10-Kerberos-Pre-Auth-Password-Spraying/
    ├── 11-Classic-Pass-the-Hash-NTLM/
    └── 12-Overpass-the-Hash-Pass-the-Key/
```

---

## Pillar 1: [Account Management & Logon Detection Labs](01-Account-Management-Event-Detection-Labs/)

Foundational purple-team labs establishing the baseline of Windows Security Event Log auditing, logon telemetry, privilege group alterations, and SOC triage playbooks.

| # | Lab | What It Proves | Key Event IDs |
|---|---|---|---|
| **01** | [RDP Logon Detection](01-Account-Management-Event-Detection-Labs/01-RDP-Logon-Detection-4624-4625/) | Remote interactive and network logons landing in SIEM — reading 4624/4625 like an analyst | 4624, 4625 |
| **02** | [Privilege Escalation Detection](01-Account-Management-Event-Detection-Labs/02-Privilege-Escalation-Detection-4728-4729/) | The classic attack pattern: account added to a privileged group, then removed — the 4728 moment | 4728, 4729 |
| **03** | [Account Lifecycle Auditing](01-Account-Management-Event-Detection-Labs/03-Account-Lifecycle-Auditing-4720-to-4740/) | Full lifecycle (create → disable → enable → delete) plus real account lockout telemetry | 4720, 4725, 4722, 4726, 4740, 4767 |
| **04** | [Brute-Force Mini-Incident: Triage](01-Account-Management-Event-Detection-Labs/04-Brute-Force-Mini-Incident-Triage/) | Failures → lockout → unlock → success, worked end-to-end as a SOC triage case with written verdict | 4625, 4740, 4767, 4624 |
| **05** | [Chained Attack: One Incident, Five Alerts](01-Account-Management-Event-Detection-Labs/05-Chained-Attack-One-Incident-Five-Alerts/) | Backdoor account → privileged group → RDP logon → process → log cleared, verified end-to-end | 4720, 4728, 4624, 4688, 1102 |
| **06** | [Rogue Admin: Purple-Team Story](01-Account-Management-Event-Detection-Labs/06-Rogue-Admin-Purple-Team/) | Attack story broken down step-by-step: evasion, what still catches it, and re-testing detection | 4720, 4728, 4624, 4688, 1102 |
| **07** | [Alert Triage SOP](01-Account-Management-Event-Detection-Labs/07-Alert-Triage-SOP/) | Tier-1/Tier-2 analyst operational SOP: one triage flow, per-alert playbooks, and escalation criteria | 4720, 4728, 4624, 4688, 1102, 4738 |

---

## Pillar 2: [Kerberos Attacks and Defense Labs](02-Kerberos-Attacks-and-Defense-Labs/)

Advanced Active Directory authentication security: dissecting Kerberos protocol mechanics (RFC 4120, RFC 4757), credential harvesting, lateral movement, encryption downgrades, and custom Wazuh detection rules.

| # | Lab | What It Proves | Key Event IDs | MITRE ATT&CK |
|---|---|---|---|---|
| **08** | [AS-REP Roasting](02-Kerberos-Attacks-and-Defense-Labs/08-Kerberos-Authentication-and-AS-REP-Roasting/) | Zero-credential pre-auth bypass, ticket extraction, Hashcat cracking, and Wazuh Rule 100117 | 4768, 4769, 4771, 4624 | T1558.004 |
| **09** | [Kerberoasting](02-Kerberos-Attacks-and-Defense-Labs/09-Kerberos-Service-Ticket-and-Kerberoasting/) | Service Principal Name (SPN) harvesting, RC4 ticket cracking, Rule 100102 (Level 12), and AES remediation | 4720, 4768, 4769, 4624, 4738 | T1558.003 |
| **10** | [Kerberos Password Spraying](02-Kerberos-Attacks-and-Defense-Labs/10-Kerberos-Pre-Auth-Password-Spraying/) | Pre-auth horizontal password spray, Event 4771 failure code `0x18`, valid TGT `0x0`, and Rule 60104 | 4771, 4768, 4624 | T1110.003 |
| **11** | [Classic Pass-the-Hash (PtH)](02-Kerberos-Attacks-and-Defense-Labs/11-Classic-Pass-the-Hash-NTLM/) | Post-compromise NTLM lateral movement, SMB file system traversal, Event 4624 `NtLmSsp`, and Level 12 Off-Hours alert | 4728, 4624, 4672, 5140 | T1550.002 |
| **12** | [Overpass-the-Hash (Pass-the-Key)](02-Kerberos-Attacks-and-Defense-Labs/12-Overpass-the-Hash-Pass-the-Key/) | RFC 4757 RC4 key derivation, converting NTLM to Kerberos TGT, Event 4768 `0x17` downgrade detection, and Kerberos masquerade | 4768, 4624, 5140 | T1550.002 |

---

### Documentation Standards

Every lab README adheres to strict enterprise purple-team reporting standards:
1. **Student Notes & Conceptual Breakthroughs:** Demystifying core security paradoxes and operational realities.
2. **Architecture & Threat Modeling:** ASCII diagrams illustrating network packets, ports, and protocol states.
3. **Red Team Attack Steps:** Reproducible commands with exact terminal outputs.
4. **Blue Team Telemetry Analysis:** Event IDs, fields, and custom Wazuh rules mapped to MITRE ATT&CK.
5. **Defensive Hardening:** GPOs, PowerShell scripts, and remediation recommendations.
6. **Photographic Evidence:** Sanitized and blurred screenshots proving live execution.
