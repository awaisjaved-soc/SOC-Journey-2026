# Core Detection Labs

The four foundational detection labs — each one a complete attack-or-scenario → event → Wazuh alert → triage loop. Work them in order; each assumes the previous lab's setup.

| # | Lab | What it proves | Key event IDs |
|---|---|---|---|
| 01 | [RDP Logon Detection](01-RDP-Logon-Detection-4624-4625/) | Remote logons as a domain user land in the SIEM — reading 4624/4625 like an analyst, including a pass-the-hash false positive | 4624, 4625 |
| 02 | [Privilege Escalation Detection](02-Privilege-Escalation-Detection-4728-4729/) | The classic attack pattern: an account added to a privileged group, then removed — the 4728 moment | 4728, 4729 |
| 03 | [Account Lifecycle Auditing](03-Account-Lifecycle-Auditing-4720-to-4740/) | The full account story (create → disable → enable → delete) plus a real lockout — and a Kerberos logging blind spot worth knowing | 4720, 4725, 4722, 4726, 4740, 4767 |
| 04 | [Brute-Force Mini-Incident: Triage](04-Brute-Force-Mini-Incident-Triage/) | Failures → lockout → unlock → success, worked end-to-end as a SOC triage case with a written verdict | 4625, 4740, 4767, 4624 |

Every lab README follows the same shape: **Overview → What Is This Lab → Lab Steps (every command explained) → What Wazuh Said → SOC Takeaways**, with screenshots embedded where they were captured.

For the deep dive that grew out of these labs — 25 account-management events mapped to Wazuh rule by rule — see [02-Account-Management-25-Events](../02-Account-Management-25-Events/).
