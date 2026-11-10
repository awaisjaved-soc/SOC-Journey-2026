# Rule 100117 — Kerberos TGT Requested (AS-REP Roasting Vector)

*Part of [Custom Detection Rules — Master Reference](README.md). Status: **TESTED** (Nov 10, 2026).*

| Field | Value |
|---|---|
| Rule ID | 100117 |
| Level | 3 |
| Event | 4768 (A Kerberos authentication ticket (TGT) was requested) |
| MITRE | **T1558.004** — Steal or Forge Kerberos Tickets: AS-REP Roasting |
| Group | `windows, security` |
| Source | Kerberos TGT Audit & Lab 08 |

## Rule

```xml
<group name="windows,security,">
  <rule id="100117" level="3">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4768$</field>
    <description>Kerberos: TGT ticket requested by $(win.eventdata.targetUserName) from $(win.eventdata.ipAddress)</description>
    <mitre>
      <id>T1558.004</id>
    </mitre>
  </rule>
</group>
```

---

## What it detects

Initial **Ticket Granting Ticket (TGT)** requests (Event 4768) against Active Directory Domain Controllers. It decodes the requesting `TargetUserName`, client `IpAddress`, and binds the event to MITRE ATT&CK technique **T1558.004** (AS-REP Roasting).

---

## Purpose

By default, Wazuh built-in rulesets (`0580-win-security_rules.xml`) drop successful 4768 events at `level 0` to prevent SIEM log volume inflation from routine user logons. 

While this saves storage, it blinds the SOC to **AS-REP Roasting attacks**. When an attacker requests a TGT for an account with `DONT_REQ_PREAUTH` enabled, the KDC issues an encrypted AS-REP blob without validating a pre-authentication timestamp. Without Rule 100117, this credential harvesting activity generates zero alerts. Rule 100117 closes this visibility gap at level 3, providing a baseline stream that can be tuned or filtered by `PreAuthType = 0`.

---

## How it works

- **`<if_sid>60103</if_sid>`** — Parent rule is the generic Windows security event listener (Rule 60103, "Windows generic security event").
- **`<field name="win.system.eventID">^4768$</field>`** — Matches Event ID 4768 strictly.
- **`<description>` with `$(win.eventdata.*)` dynamic substitution** — Injects the requesting username and IP dynamically into the alert description.
- **MITRE T1558.004 mapping** — Flags the alert in Wazuh Threat Hunting dashboards under credential access.

---

## Shadowing and dependencies

- **Does not shadow 60104:** Event 4771 (Kerberos pre-authentication failed) fires Rule 60104; Rule 100117 only matches 4768.
- **Suppresses Rule 60103:** Since Rule 100117 is a child of 60103 with higher specificity, it promotes the event from generic level 0 to an actionable level 3 alert.
- **Dependency:** Requires `Audit Kerberos Authentication Service` to be configured for `Success and Failure` on the Domain Controller.

---

## Test Evidence

Tested and verified live in the SOC lab environment on November 10, 2026. The alert fired 13 times when requesting TGTs for `victim-asrep` from `WIN-SOCLAB` (192.168.100.146).

<img width="1919" height="553" alt="image" src="https://github.com/user-attachments/assets/ee9d310d-ff8e-4978-8165-abe336e29b84" />


---

<img width="962" height="891" alt="image" src="https://github.com/user-attachments/assets/fc41a5fb-0e72-463a-aac6-0a3a79dfafb0" />

---

<img width="998" height="525" alt="image" src="https://github.com/user-attachments/assets/e442f9dc-a463-4a58-91f7-b8f3717d7143" />

---


<img width="993" height="430" alt="image" src="https://github.com/user-attachments/assets/592ef6ba-8d03-4472-956f-8a461114b173" />

---



*Wazuh Threat Hunting view showing 13 hits for Rule 100117 (level 3) displaying "Kerberos: TGT ticket requested by victim-asrep from 192.168.100.146".*

---

## Triage Guidance & DQL

In the Wazuh **Threat Hunting** dashboard, search for anomalous TGT issuance:

```sql
rule.id: 100117 AND data.win.eventdata.preAuthType: "0"
```

Any hit from this query means an account with Kerberos pre-authentication disabled requested a TGT — investigate the source IP and target user immediately.
