# 04 — Audit Policy Setup: Turning the Events On

*The lab that makes every other lab work. No audit policy, no events. No events, no detections.*

---
## Overview

Windows does not log most security events by default. A fresh Windows Server install leaves the majority of audit subcategories at **No Auditing** — the events simply never exist, and no Wazuh rule in the world can fire on an event that was never written.

This folder documents the audit policy for the whole lab: what was off, how to check it, the full enable list, and how to verify it stuck. It exists because of a real failure: on the rebuilt domain controller, the chained-attack lab's Step 4 (process creation, event 4688) returned **"No results match your search criteria"** — not because the process never ran, but because `Process Creation` auditing was off. The account creation (4720), the group add (4728), and the RDP logon (4624) all worked on the same server, because their subcategories happened to be on already. That split — some events flowing, one silently absent — is the signature of an audit-policy gap.

---
## Why audit policy matters

Wazuh reads the Windows Security log. The audit policy decides what Windows writes into it. The mapping is one subcategory → many events:

| Subcategory | Events it unlocks |
|---|---|
| User Account Management | 4720, 4722, 4725, 4726, 4738, 4740 |
| Security Group Management | 4728, 4729, 4732, 4733, 4734, 4737 |
| Logon | 4624, 4625, 4634 |
| Kerberos Authentication Service | 4768, 4771 |
| Process Creation | 4688 |
| Audit Policy Change | 4719 |
| Sensitive Privilege Use | 4672, 4673, 4674 |

If a subcategory is off, every event under it is invisible — including to the archives index and to `Get-WinEvent` on the DC. When an expected event is missing, check the audit policy **before** suspecting Wazuh, the agent, or the rule. (The same lesson already appeared with 4771: Kerberos pre-authentication failures never logged until the Kerberos Authentication Service subcategory was enabled — while the account still locked out, because the lockout does not depend on the log.)

---
## Before-state — this lab, November 5, 2026

The domain controller was rebuilt with a fresh Windows install. `auditpol /get /category:*` showed:

**Already on (Success) — which is why these worked:**
- User Account Management, Security Group Management, Computer Account Management — 4720 and 4728 fired
- Logon (Success and Failure), Credential Validation, Kerberos Authentication Service, Kerberos Service Ticket Operations — 4624 and 4625 fired
- Directory Service Access, Audit Policy Change, Authentication Policy Change, Security State Change, System Integrity, Special Logon, Account Lockout, Logoff

**Off (No Auditing) — which is why these were missing:**
- Process Creation, Process Termination, DPAPI Activity, RPC Events — **no 4688 at all**
- File System, Registry, SAM, File Share, Handle Manipulation — no object-access events
- Filtering Platform Connection, Filtering Platform Packet Drop — no firewall-connection events
- Sensitive Privilege Use, Non Sensitive Privilege Use, Other Privilege Use Events — no 4672/4673/4674
- Distribution Group Management, Application Group Management, Other Account Management Events, Directory Service Changes — gaps in the account-management coverage
- Other Logon/Logoff Events, Group Membership, Authorization Policy Change, MPSSVC Rule-Level Policy Change, Filtering Platform Policy Change, Other Policy Change Events — gaps in logon and policy-change coverage

---
## How to check

On the domain controller, in an elevated PowerShell (Run as Administrator):

```
auditpol /get /category:*
```

For one subcategory:

```
auditpol /get /subcategory:"Process Creation"
```

The setting column shows `Success`, `Failure`, `Success and Failure`, or `No Auditing`. Anything you need must show `Success and Failure` (or at least `Success` for success-only events).

---
## The full enable list

Run these on the domain controller as Administrator. `auditpol /set` is idempotent — running it again on an already-enabled subcategory changes nothing, so it is safe to re-run the whole list after a rebuild.

```
# Account Logon - 4625, 4771, 4768, 4769
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Account Management - 4720, 4728, 4732, 4738, 4740
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable

# Detailed Tracking - 4688, 4689
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
auditpol /set /subcategory:"DPAPI Activity" /success:enable /failure:enable
auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable

# DS Access
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Logon/Logoff - 4624, 4625, 4634, 4648, 4672
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Group Membership" /success:enable /failure:enable

# Object Access - file, registry, share, firewall
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable

# Policy Change - 4719, audit policy change
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable

# Privilege Use - 4672, 4673, 4674
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Other Privilege Use Events" /success:enable /failure:enable

# System - 4608, 4612, 4616, 4697, 1102 related
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable
```

Every command prints `The command was successfully executed.` when it lands. If a subcategory name is ever rejected, check the exact name with `auditpol /get /category:*` — names differ between Windows versions.

---
## How to verify

After the list, run the check again and confirm nothing still says `No Auditing` for a subcategory you need:

```
auditpol /get /category:*
```

Then prove it with an event, not with the output: generate a 4688 and look for it.

```powershell
notepad.exe
```

```
data.win.system.eventID: 4688 AND data.win.eventdata.subjectUserName: <your-user>
```

If the 4688 appears, `Process Creation` is on. The same test works for any subcategory — generate the event, then hunt it. The chained-attack lab ([05-Chained-Attack-One-Incident-Five-Alerts](../01-Core-Detection-Labs/05-Chained-Attack-One-Incident-Five-Alerts/)) is the end-to-end proof: its Step 4 only exists because this setup ran first.

Note: changing audit policy itself generates 4719 events (Audit Policy Change) — expect a burst of them right after running the list. That is the audit trail of the change, not an attack.

---
## Warning — Group Policy can override this

On a domain controller, audit policy is normally controlled by **Group Policy**, not by local `auditpol`. A local `auditpol /set` works until the next Group Policy refresh, which can silently revert it to whatever the policy says.

If settings revert, or if this lab needs to survive rebuilds, make the same change durable in Group Policy:

1. Open **Group Policy Management** (`gpmc.msc`) on the DC.
2. Edit **Default Domain Controllers Policy**.
3. Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies.
4. Enable the same subcategories there (Success and Failure), then run `gpupdate /force`.

Local `auditpol` is the fast lab fix. Group Policy is the durable one.

---
## Warning — noise

Enabling everything has a cost: volume. These three generate the most noise, by far:

- **File System** — an event for every audited file access. Without SACLs on specific files/folders it is mostly noise; the subcategory alone does not make file auditing useful, it just turns the tap on.
- **Registry** — same story as File System, for registry keys.
- **Filtering Platform Connection** — an event per network connection (5156). On a busy server this is a flood.

In this lab that volume is acceptable — the point is coverage while learning. In production you would enable these selectively and tune with SACLs and exclusions. If Wazuh starts flooding after this list, tune those three first.

---
## Sysmon is separate

None of this touches Sysmon. Sysmon is its own sensor with its own config (`Sysmon64 -i`), and its events arrive through the separate `Microsoft-Windows-Sysmon/Operational` channel in the Wazuh agent's `ossec.conf`. Sysmon 1 (process creation), 11 (file creation), and 13 (registry value set) do not depend on `auditpol` at all — which is exactly why the Sysmon 11 FileCreate for PowerShell's `__PSScriptPolicyTest` file was visible in Wazuh while the 4688 for the same session was not. When the Windows audit trail is silent, Sysmon is the second witness.

---

*Part of [Wazuh Home SOC Lab](../README.md) — set the audit policy before you trust any detection built on it.*
