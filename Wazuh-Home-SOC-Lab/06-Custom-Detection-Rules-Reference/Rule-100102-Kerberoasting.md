# Rule 100102 — Possible Kerberoasting (RC4 Service Ticket Requested)

*Part of [Custom Detection Rules — Master Reference](README.md). Status: **UNTESTED**.*

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

A Kerberos service ticket (event 4769) requested with **RC4 encryption** (ticket encryption type `0x17`). RC4 tickets can be cracked offline — that is the Kerberoasting attack: request a ticket for a service account, take it home, crack it, and you have the service account's password.

## Purpose

Event 4769 fires on every legitimate service-ticket request, so the event alone is noise. The narrowing condition is the encryption type: modern services negotiate AES, so an RC4 ticket stands out as either a legacy service or an attacker deliberately requesting the weakest encryption so the ticket is crackable. Level 12 expresses that this is a credential-theft pattern, not a routine ticket.

## How it works

- **`<if_group>windows</if_group>`** — only events decoded by the Windows decoder are evaluated.
- **`<field name="win.system.eventID">^4769$</field>`** — the event must be a Kerberos service-ticket request (4769). The `^...$` anchors mean an exact match.
- **`<field name="win.eventdata.ticketEncryptionType">0x17</field>`** — the ticket must use RC4 encryption (`0x17`). An AES ticket (`0x12` for AES256, `0x11` for AES128) does not match, so normal traffic stays silent.
- **Level 12** — high, because a cracked service-account password is domain-wide credential theft, not a single-machine event.

## Shadowing and dependencies

- **No parent, no shadowing.** This is an independent rule (no `<if_sid>`). It does not suppress any built-in rule, and no built-in rule suppresses it.
- **Depends on event 4769 being generated and decoded.** The 4769 row in the Phase 2 sheet is still "verify in lab" — the built-in rule ID and level for 4769 have not been confirmed from a fired alert yet. If 4769s are not flowing (audit subcategory, or the event not generated), this rule is blind through no fault of its own.

## Test evidence / test plan

**UNTESTED** — this rule has not been run in the lab. Test plan:

1. First verify 4769 is flowing: request a service ticket in the lab (e.g. access a share or service as a domain user) and confirm a 4769 alert appears in Threat Hunting. Note the built-in rule ID and level, and fill the Phase 2 sheet row.
2. Positive: request a ticket with RC4 encryption (e.g. against a service account configured for RC4, or with a tool that requests RC4) → rule 100102 fires at level 12.
3. Negative: a normal AES ticket request → no 100102 alert (the built-in 4769 rule fires, this one stays silent).
4. Record the service account, the encryption type on the alert, and the ticket's target service name.

## Find it in Wazuh

```
rule.id: 100102
```

## MITRE ATT&CK

**T1558.003 — Kerberoasting.** Adversaries request a Kerberos service ticket for a service account, then crack it offline to recover the account's password. Service accounts often have weak passwords and broad privileges, so one cracked ticket can mean domain-wide access.
