# Kerberos Attacks and Defense Master Series

*Part of the [Core Detection Labs](../README.md) — an advanced purple-team curriculum dissecting Kerberos authentication protocol internals (RFC 4120, RFC 4757), credential harvesting, lateral movement, and SIEM detection engineering.*

---

## Overview

Active Directory enterprise environments rely on **Kerberos** as their default authentication protocol. While robust when properly configured, architectural design choices, legacy compatibility flags, and misconfigurations create attack surfaces across the entire intrusion lifecycle.

This master series documents the complete theory, red-team exploitation mechanics, blue-team Windows Event Log analysis, and custom **Wazuh 4.14.5** detection rules across five core techniques.

---

## Master Lab Index

```text
02-Kerberos-Attacks-and-Defense-Labs/
├── 08-Kerberos-Authentication-and-AS-REP-Roasting/     # MITRE T1558.004 — Pre-Auth Bypass & AS-REP Extraction
├── 09-Kerberos-Service-Ticket-and-Kerberoasting/       # MITRE T1558.003 — SPN Harvesting & TGS RC4 Cryptanalysis
├── 10-Kerberos-Pre-Auth-Password-Spraying/             # MITRE T1110.003 — Event 4771 Status 0x18 Telemetry
├── 11-Classic-Pass-the-Hash-NTLM/                      # MITRE T1550.002 — DRSUAPI Extraction & NtLmSsp Lateral Movement
└── 12-Overpass-the-Hash-Pass-the-Key/                  # MITRE T1550.002 — RFC 4757 RC4 Downgrade (0x17) & Masquerade
```

| # | Lab | Attack Vector | Key Telemetry Signature | Primary SIEM Rule | MITRE ATT&CK |
|---|---|---|---|---|---|
| **08** | [AS-REP Roasting](08-Kerberos-Authentication-and-AS-REP-Roasting/) | Zero-credential ticket request for accounts with `DONT_REQ_PREAUTH` enabled | Event 4768 (`PreAuthType: 0`) followed by offline ticket hash cracking | Rule 100117 | **T1558.004** |
| **09** | [Kerberoasting](09-Kerberos-Service-Ticket-and-Kerberoasting/) | Requesting TGS service tickets for accounts with static Service Principal Names (SPNs) | Event 4769 (`TicketEncryptionType: 0x17` RC4) | Rule 100102 (Level 12) | **T1558.003** |
| **10** | [Kerberos Password Spray](10-Kerberos-Pre-Auth-Password-Spraying/) | Testing single passwords against multiple accounts via Kerberos pre-authentication | Event 4771 (`Status: 0x18` `KDC_ERR_PREAUTH_FAILED`) | Rule 60104 / 100117 | **T1110.003** |
| **11** | [Classic Pass-the-Hash](11-Classic-Pass-the-Hash-NTLM/) | Lateral movement using stolen NTLM hash directly over SMB Port 445 without cleartext password | Event 4624 (`LogonType: 3`, `NtLmSsp`, `NTLM V2`) | Rule 100115 (Level 12) | **T1550.002** |
| **12** | [Overpass-the-Hash](12-Overpass-the-Hash-Pass-the-Key/) | Converting stolen NTLM hash into genuine Kerberos TGT via RFC 4757 RC4-HMAC key derivation | Event 4768 (`TicketEncryptionType: 0x17` Downgrade) + Event 4624 (`Kerberos`) | Rule 100117 / 100115 | **T1550.002** |

---

## The Key Blue Team Telemetry Triad

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             KERBEROS TELEMETRY TRIAD                             │
├──────────────────────┬────────────────────────┬──────────────────────────────────┤
│ Event ID             │ Protocol Stage         │ Primary Detection Angle          │
├──────────────────────┼────────────────────────┼──────────────────────────────────┤
│ Event ID 4768        │ TGT Request (AS-REQ)   │ PreAuthType: 0 (AS-REP Roast)    │
│                      │                        │ EncryptionType: 0x17 (Overpass)  │
├──────────────────────┼────────────────────────┼──────────────────────────────────┤
│ Event ID 4769        │ TGS Request (TGS-REQ)  │ EncryptionType: 0x17 (Kerberoast)│
│                      │                        │ High volume anomalous requests   │
├──────────────────────┼────────────────────────┼──────────────────────────────────┤
│ Event ID 4771        │ Pre-Auth Failure       │ Status: 0x18 (Password Spray)    │
│                      │                        │ Status: 0x25 (Clock Skew)        │
└──────────────────────┴────────────────────────┴──────────────────────────────────┘
```
