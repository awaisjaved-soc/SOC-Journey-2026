
# Category 6 — Network & Firewall Events

**Category:** Network & Firewall  
**Lab Environment:** Windows Server 2022 — TECHCORP / techcorp.local  
**Author:** SOC Journey 2026 — github.com/awaisjaved-soc/SOC-Journey-2026

---

## What Is This Category and Why Does It Matter

Every category documented before this one focused on what happens **on** the machine — processes created, registry keys modified, accounts changed, logs cleared. Category 6 is different. These events focus on what the machine is **communicating with** — what connections are being made, what packets are being dropped, and when someone changes the firewall rules that control that traffic.

In a real SOC, network events are where Command and Control (C2) traffic gets detected. After an attacker establishes a foothold on a machine, their malware needs to phone home — connect to the attacker's server to receive instructions, exfiltrate data, or download additional tools. That outbound connection generates Event 5156. If the firewall blocks it, you get 5157. If the attacker modifies firewall rules to ensure their traffic gets through, you get 4946 or 4947. If they set up a listener for incoming connections, you get 5154 and 5158.

These nine events together tell the complete network-layer story of an attack.

---

## Two Groups in This Category

This category splits into two clearly distinct groups with different audit policies, different volumes, and different SOC use cases.

### Group 1 — Windows Filtering Platform Connection Events

| Event ID | Name | Volume | Primary Use |
|---|---|---|---|
| 5156 | Network Connection Allowed | Very High | C2 detection, lateral movement |
| 5157 | Network Connection Blocked | Medium | Failed C2, port scan detection |
| 5152 | Packet Dropped by WFP | High | Port scan detection, packet-level drops |
| 5154 | Application Listening on Port | Low-Medium | Backdoor listener detection |
| 5158 | Port Bind Allowed | High | Socket-level bind monitoring |

These events track individual network connections at the kernel level through Windows Filtering Platform. They are noisy — 5156 and 5158 fire hundreds of times per minute on an active Domain Controller from legitimate Windows activity. Always filter by process name or destination before reviewing.

### Group 2 — Windows Firewall Rule Events

| Event ID | Name | Volume | Primary Use |
|---|---|---|---|
| 4946 | Firewall Rule Added | Low | Detect new rules opening ports |
| 4947 | Firewall Rule Modified | Low | Detect scope expansion of existing rules |
| 4948 | Firewall Rule Deleted | Low | Detect removal of protection rules |
| 4954 | Firewall Group Policy Changed | Low | Domain-wide firewall policy changes |

These events track changes to the Windows Firewall ruleset itself — not individual connections but changes to the rules that govern connections. Low volume, high signal. These are more immediately actionable than the WFP connection events.

---

## Audit Policy Setup

### For WFP Connection Events (5152, 5154, 5156, 5157, 5158)

```cmd
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
```

### For Firewall Rule Events (4946, 4947, 4948, 4954)

```cmd
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
```

### Verify All Policies Are Active

```cmd
auditpol /get /subcategory:"Filtering Platform Connection"
auditpol /get /subcategory:"Filtering Platform Packet Drop"
auditpol /get /subcategory:"MPSSVC Rule-Level Policy Change"
```

All three should show `Success and Failure`.

### Disable High-Volume Auditing After Lab

After completing WFP connection event labs, disable the noisy subcategories to prevent your Security log from flooding:

```cmd
auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:disable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:disable
```

Keep the firewall rule policy active — it is low volume and always useful:

```cmd
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
```

---

## Volume Warning — Domain Controllers

On a Domain Controller, enabling Filtering Platform Connection auditing will immediately flood your Security log with thousands of events from `lsass.exe`. This process handles all Kerberos authentication and creates a new socket for every single authentication operation in the domain. Each socket generates multiple 5156 and 5158 events.

This is completely normal. When running detection commands for lab purposes, always filter by specific process names, destination IPs, or port numbers. Never review raw unfiltered output for these events on a DC.

---

## Folder Structure

```
Category6-Network-Firewall-Events/
│
├── README.md                                        ← This file
│
├── Event-5156_Network-Connection-Allowed/
│   └── README.md
│
├── Event-5157_Network-Connection-Blocked/
│   └── README.md
│
├── Event-5152_Packet-Dropped/
│   └── README.md
│
├── Event-5154_Application-Listening/
│   └── README.md
│
├── Event-5158_Port-Bind-Allowed/
│   └── README.md
│
├── Event-4946_Firewall-Rule-Added/
│   └── README.md
│
├── Event-4947_Firewall-Rule-Modified/
│   └── README.md
│
├── Event-4948_Firewall-Rule-Deleted/
│   └── README.md
│
└── Event-4954_Firewall-Group-Policy-Changed/
    └── README.md
```

---

## Attack Chain — How These Events Tell the Full Network Story

```
Attacker compromises machine and establishes backdoor
    → 5154 fires  — backdoor opens listener on unusual port
    → 5158 fires  — port bind confirmed at socket level

Malware attempts to connect to C2 server
    → 5156 fires  — connection allowed (attacker using port 443)
    OR
    → 5157 fires  — connection blocked (firewall stopping it)
    → 5152 fires  — packet dropped at WFP level

Attacker modifies firewall to ensure C2 traffic gets through
    → 4948 fires  — existing block rule deleted
    → 4946 fires  — new allow rule added for attacker's port
    → 4947 fires  — existing rule expanded to include attacker's destination

Attacker pushes firewall change via Group Policy to all machines
    → 4954 fires  — on every machine receiving the changed policy
```

Seeing this chain in a SIEM within a short time window, from the same machine or account, is a high-confidence indicator of an active compromise with the attacker actively working to maintain network access.

---

## SOC Priority Reference

| Priority | Event | What to Do |
|---|---|---|
| 🔴 High | 4946 | New inbound allow rule — what port, what process, who added it |
| 🔴 High | 4948 | Block rule deleted — what traffic is now unblocked |
| 🔴 High | 5154 | Unknown process listening on unusual port — possible backdoor |
| 🔴 High | 4954 | Firewall Group Policy changed — domain-wide impact, verify immediately |
| 🟠 Medium | 5157 | Blocked connection — look for patterns of many blocks from one process |
| 🟠 Medium | 4947 | Firewall rule modified — what changed and was it authorized |
| 🟠 Medium | 5158 | Port bind — correlate with 5154, filter out system noise |
| 🟡 Low-Medium | 5156 | Allowed connection — filter heavily by process and destination |
| 🟡 Low-Medium | 5152 | Packet drop — useful for scan detection, high volume otherwise |

---

## Key Concept — Visible vs Silent Events

Unlike most events in previous categories, some network events have visible side effects:

**Visible:**
- 5157 — connection attempt will fail/timeout in the calling application
- 5152 — connection attempt will fail in the calling application
- 4946/4947/4948 — changes visible in `wf.msc` firewall rule list

**Silent:**
- 5156 — connection succeeds normally, no visible indicator
- 5154/5158 — listener opens silently, no GUI, no notification
- 4954 — Group Policy applies silently in the background

---

## Lab Environment

- **OS:** Windows Server 2022
- **Domain:** TECHCORP / techcorp.local
- **Server:** WIN-KAHJ94DKN9V
- **IP:** 192.168.100.129
- **Virtualisation:** VirtualBox
- **Test Accounts:** Administrator, scott, alexrivera
