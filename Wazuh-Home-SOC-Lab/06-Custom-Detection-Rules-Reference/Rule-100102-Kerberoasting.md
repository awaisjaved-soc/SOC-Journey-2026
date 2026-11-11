# Rule 100102 — Possible Kerberoasting (RC4 Service Ticket Requested)

*Part of [Custom Detection Rules — Master Reference](README.md). Status: **TESTED**.*

| Field | Value |
|---|---|
| Rule ID | 100102 |
| Level | 12 |
| Event | 4769 (Kerberos service ticket requested), ticket encryption type RC4 (0x17) |
| MITRE | **T1558.003** — Kerberoasting |
| Group | `credential_access` |
| Source | Rule pack (`local_rules.xml`, 100100–100108) |

## Rule

```xml
<rule id="100102" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4769$</field>
  <field name="win.eventdata.ticketEncryptionType">0x17</field>
  <description>Possible Kerberoasting: RC4-encrypted Kerberos service ticket requested (event 4769)</description>
  <mitre>
    <id>T1558.003</id>
  </mitre>
  <group>credential_access,</group>
</rule>
```

## What it detects

A Kerberos service ticket (event 4769) requested with **RC4 encryption** (ticket encryption type `0x17`). RC4 tickets can be cracked offline — that is the Kerberoasting attack: request a ticket for a service account, extract the ciphertext hash, crack it offline, and recover the service account's plaintext password.

## Purpose

Event 4769 fires on every legitimate service-ticket request, so the event alone is noise. The narrowing condition is the encryption type: modern services negotiate AES, so an RC4 ticket stands out as either a legacy service or an attacker deliberately requesting the weakest encryption so the ticket is crackable. Level 12 expresses that this is a credential-theft pattern, not a routine ticket.

## How it works

- **`<if_group>windows</if_group>`** — only events decoded by the Windows decoder are evaluated.
- **`<field name="win.system.eventID">^4769$</field>`** — the event must be a Kerberos service-ticket request (4769). The `^...$` anchors mean an exact match.
- **`<field name="win.eventdata.ticketEncryptionType">0x17</field>`** — the ticket must use RC4 encryption (`0x17`). An AES ticket (`0x12` for AES256, `0x11` for AES128) does not match, so normal traffic stays silent.
- **Level 12** — high, because a cracked service-account password is domain-wide credential theft, not a single-machine event.

## Shadowing and dependencies

- **No parent, no shadowing.** This is an independent rule (no `<if_sid>`). It evaluates directly on incoming Windows Security channel events.
- **Depends on event 4769 flowing.** Generated when the **Kerberos Service Ticket Operations** audit subcategory is enabled on the Domain Controller.

## Test evidence

**TESTED** — verified live in [Lab 09 — Kerberos Service Ticket Request & Kerberoasting Incident Triage](../01-Core-Detection-Labs/09-Kerberos-Service-Ticket-and-Kerberoasting/) on November 11, 2026.

1. **Adversary Emulation:** Kali Linux (`192.168.100.50`) executed `impacket-GetUserSPNs` against Domain Controller (`192.168.100.146`) querying SPN `MSSQLSvc/db01.soclab.local:1433`.
2. **SIEM Detection:** Wazuh fired Rule **100102** at **Level 12** on Event 4769.
   - `TargetUserName`: `svc-mssql`
   - `ServiceName`: `MSSQLSvc/db01.soclab.local:1433`
   - `TicketEncryptionType`: `0x17` (RC4-HMAC)
   - `IpAddress`: `192.168.100.50`
   - `Status`: `0x0` (Audit Success)
3. **Remediation Verification:** Account updated with `Set-ADUser -KerberosEncryptionType AES128,AES256`. Subsequent TGS queries issued `$krb5tgs$18$` (AES-256), completely stopping Rule 100102 alerts and defeating offline cracking.

## Find it in Wazuh

```
rule.id: 100102
```

## MITRE ATT&CK

**T1558.003 — Kerberoasting.** Adversaries request a Kerberos service ticket for a service account, then crack it offline to recover the account's password. Service accounts often have weak passwords and broad privileges, so one cracked ticket can mean domain-wide access.
