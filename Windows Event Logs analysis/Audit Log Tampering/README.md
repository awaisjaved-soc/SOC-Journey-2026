# Category 4 — Audit & Log Tampering Events

**Focus:** Anti-Forensics / Log Tampering / Policy Manipulation  
**Lab Environment:** Windows Server 2022 — TECHCORP / techcorp.local  
**Total Events:** 9

---

## What Is This Category and Why Does It Matter

Every previous category documented in this repository covers events that fire when an attacker **does** something (process creation, service installation, registry modification, WMI persistence, etc.).

This category is different. These events fire when an attacker tries to **undo the evidence** of what they did.

After an attacker has run commands, created persistence, or moved laterally, they often attempt to blind defenders by:

- Clearing the Security log
- Stopping the Event Log service
- Disabling specific audit policies
- Removing auditing from sensitive objects
- Weakening domain policies
- Creating or removing domain trusts

This is called **anti-forensics**. It is one of the strongest indicators that you are dealing with a skilled attacker rather than simple malware. Script kiddies rarely clean up. APT groups almost always do.

The events in this category answer one critical question during an incident:

> **Did the attacker try to blind us?**

If the answer is yes, the severity of the incident increases significantly. You can no longer fully trust the local log timeline.

---

## Events in This Category

| Event ID | Name | Priority | Lab Status |
|----------|------|----------|------------|
| [1102](./Event-1102_Audit-Log-Cleared/) | Audit Log Cleared | 🔴 Critical | ✅ Generated |
| [1100](./Event-1100_Event-Log-Service-Stopped/) | Event Log Service Stopped | 🔴 Critical | ⚠️ Protected on modern Windows |
| [4719](./Event-4719_Audit-Policy-Changed/) | System Audit Policy Changed | 🔴 High | ✅ Generated |
| [4739](./Event-4739_Domain-Policy-Changed/) | Domain Policy Changed | 🔴 High | ✅ Generated (DC only) |
| [4907](./Event-4907_Audit-Settings-Object-Changed/) | Audit Settings on Object Changed | 🟠 High | ✅ Generated |
| [4906](./Event-4906_CrashOnAuditFail-Changed/) | CrashOnAuditFail Value Changed | 🟡 Medium | ✅ Generated |
| [4713](./Event-4713_Kerberos-Policy-Changed/) | Kerberos Policy Changed | 🟠 High | ✅ Generated (DC only) |
| [4706](./Event-4706_New-Trust-Created/) | New Trust Created to Domain | 🔴 Critical | ⚠️ Requires second domain |
| [4707](./Event-4707_Trust-Removed/) | Trust to Domain Removed | 🟠 High | ⚠️ Requires existing trust |

---

## Pre-Lab Setup

Enable the required audit policies before starting:

```cmd
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable
```

Verify:

```cmd
auditpol /get /category:"Policy Change"
auditpol /get /category:"System"
```

---

## Attack Chain Correlation

These events often appear together in real attacks:

```
Phase 1 — Surgical blinding before the attack
  4719  →  Disable specific audit subcategories
  4907  →  Remove SACL from target files/folders
  4906  →  Disable CrashOnAuditFail

Phase 2 — The attack happens (many events missing because auditing was disabled)

Phase 3 — Covering tracks
  1100  →  Event Log service stopped (if possible)
  1102  →  Security log cleared
  4719  →  Re-enable audit policies (to look normal)

Phase 4 — Domain-level persistence / impact
  4706  →  New malicious domain trust
  4739  →  Domain lockout policy weakened
  4713  →  Kerberos ticket lifetime extended
  4707  →  Trust removed later (cleanup)
```

---

## SOC Priority Reference

| Priority | Event | Recommended Action |
|----------|-------|--------------------|
| 🔴 Immediate | 1102 | Assume compromise. Investigate everything before the clear. |
| 🔴 Immediate | 1100 | Logging stopped mid-session — examine the blind spot. |
| 🔴 Immediate | 4706 | New domain trust — verify with domain admins immediately. |
| 🔴 High | 4719 | Audit policy disabled — what was the attacker trying to hide? |
| 🔴 High | 4739 | Domain policy weakened — check for follow-on brute force. |
| 🟠 Investigate | 4907 | SACL removed — what happened to that object afterward? |
| 🟠 Investigate | 4713 | Kerberos policy changed — look for ticket-based attacks. |
| 🟠 Investigate | 4707 | Trust removed — business impact or attacker cleanup? |
| 🟡 Monitor | 4906 | CrashOnAuditFail changed — correlate with log flooding. |

---

## Folder Structure

```
Category4-Audit-Log-Tampering/
│
├── README.md                          ← This file
│
├── Event-1102_Audit-Log-Cleared/
├── Event-1100_Event-Log-Service-Stopped/
├── Event-4719_Audit-Policy-Changed/
├── Event-4739_Domain-Policy-Changed/
├── Event-4907_Audit-Settings-Object-Changed/
├── Event-4906_CrashOnAuditFail-Changed/
├── Event-4713_Kerberos-Policy-Changed/
├── Event-4706_New-Trust-Created/
└── Event-4707_Trust-Removed/
```

Each event folder contains a detailed README with:

- Event overview and explanation
- Why it matters for SOC
- Lab generation steps (GUI + Command line)
- Detection methods
- Key fields
- SOC investigation notes and MITRE mapping

---

**This category completes the core Windows Event Log anti-forensics coverage for the SOC Journey.**
