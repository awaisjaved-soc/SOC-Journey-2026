# 🔐 Active Directory & LDAP Enumeration — Port 389 | Practical Lab

**Author:** Muhammad Awais Javed (Mian Awais)
**Date:** May 2026
**Part of:** [SOC-Journey-2026](https://github.com/awaisjaved-soc/SOC-Journey-2026)

**Domain:** `techcorp.local` · **DC IP:** `192.168.100.110` · **Attacker:** Kali Linux (`192.168.100.90`) · **Target:** Windows Server 2022

---
## 📌 Table of Contents
- [🎯 Objective](#-objective)
- [📖 What is LDAP?](#-what-is-ldap)
- [📖 What is Active Directory?](#-what-is-active-directory)
- [⚙️ How It Works](#️-how-it-works)
- [🧪 Lab Environment](#-lab-environment)
- [💻 Commands Used](#-commands-used)
- [🔍 Wireshark Analysis](#-wireshark-analysis)
- [🚨 SOC Analyst Notes](#-soc-analyst-notes)
- [🛡️ MITRE ATT&CK](#️-mitre-attck)
- [📸 Screenshots](#-screenshots)
- [✅ Key Takeaways](#-key-takeaways)

---
## 🎯 Objective

- Build a full **Windows Server 2022 Active Directory domain** (`techcorp.local`) with realistic departments and users
- Enumerate the entire directory from Kali Linux using `ldapsearch` — the way real attackers do reconnaissance
- Run **targeted LDAP queries**: find admins, weak accounts, password policy, and Kerberoasting targets
- Capture the traffic in Wireshark and prove LDAP on port 389 is **plaintext**
- Write it up as a findings report, the way a pentester or SOC analyst would

---
## 📖 What is LDAP?

**LDAP (Lightweight Directory Access Protocol)** is the protocol used to access and manage directory information over a network. Think of it as a **phone book for a company network** — it stores information about users, computers, groups, departments, and permissions.

- **Port:** 389 (plain) | 636 (LDAPS — encrypted)
- **Protocol type:** TCP
- **Used by:** Active Directory, OpenLDAP, email clients, HR systems, VPNs

Every time an employee logs into their work laptop, their computer is talking LDAP in the background — asking the server *"is this password correct?"*

### LDAP structure (DN — Distinguished Name)

```
DC=techcorp,DC=local          ← Root of the domain
├── OU=IT                      ← Department (Organizational Unit)
│   ├── CN=Mian Awais          ← User object
│   └── CN=Hamza Khan
├── OU=HR
│   └── CN=Ayesha Khan
├── OU=Finance
│   └── CN=Fatima Ahmed
└── CN=Users                   ← Default container
    └── CN=Administrator
```

| LDAP Term | Meaning |
|-----------|---------|
| `DC` | Domain Component (`techcorp`, `local`) |
| `OU` | Organizational Unit (a department) |
| `CN` | Common Name (user or group name) |
| `DN` | Distinguished Name (full path to an object) |

---
## 📖 What is Active Directory?

**Active Directory (AD)** is Microsoft's implementation of LDAP. It is the central identity and access management system used in almost every medium-to-large company worldwide.

**What AD stores:**
- All user accounts (name, email, phone, department, title)
- All computer accounts
- All groups and their members
- Password policies
- Access permissions (who can reach what folder/system)

**Real-world analogy:** AD is the company's HR database + security guard + phone book, all in one.

**Why SOC analysts care:** when attackers get inside a network, the first thing they do is enumerate AD over LDAP. Understanding this traffic is core to detecting and stopping them.

---
## ⚙️ How It Works

A typical LDAP session between attacker and domain controller:

```
[ Kali Linux / Attacker ]                [ Windows Server DC ]
         |                                        |
         |--- 1. TCP connect to port 389 -------> |
         |--- 2. BIND Request (user + pass) ----> |
         |<-- 3. BIND Response (success/fail) --- |
         |--- 4. SEARCH Request (query) --------> |
         |<-- 5. SEARCH Results (user data) ----- |
         |--- 6. UNBIND (disconnect) -----------> |
```

The **BIND** operation is authentication. Once you bind successfully with **any** valid user account, you can search the entire directory — because AD is designed so employees can look up colleagues. That design choice is exactly what attackers exploit.

---
## 🧪 Lab Environment

```
┌─────────────────────────────────────────────────────┐
│                   HOME LAB NETWORK                   │
│                  192.168.100.0/24                    │
│                                                      │
│  ┌──────────────────────┐   ┌─────────────────────┐  │
│  │  Windows Server VM   │   │    Kali Linux        │  │
│  │ (Domain Controller)  │   │    (Attacker)        │  │
│  │  IP: 192.168.100.110 │   │    IP: 192.168.100.90│  │
│  │  OS: Win Server 2022 │   │    Tools: ldapsearch │  │
│  │  Domain: techcorp    │   │    nmap, hydra       │  │
│  │  Role: AD DS         │   │    Wireshark         │  │
│  └──────────────────────┘   └─────────────────────┘  │
│         Both on same NAT / Host-Only network         │
└─────────────────────────────────────────────────────┘
```

**Prerequisites I used:** VMware/VirtualBox, Windows Server 2022 ISO (free evaluation from Microsoft), Kali Linux ISO.

---
## 💻 Commands Used

### On Windows Server — build the domain

Open PowerShell **as Administrator**:

```powershell
# Install the Active Directory Domain Services role
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

# Promote this server to a Domain Controller (restarts automatically)
Install-ADDSForest `
  -DomainName "techcorp.local" `
  -DomainNetbiosName "TECHCORP" `
  -InstallDns:$true `
  -Force:$true
```

```powershell
# Verify the domain services are running
Get-Service ADWS, NTDS, DNS, Netlogon

# Confirm the domain exists
Get-ADDomain
```

### Create departments (Organizational Units)

```powershell
# One OU per department
New-ADOrganizationalUnit -Name "IT"         -Path "DC=techcorp,DC=local"
New-ADOrganizationalUnit -Name "HR"         -Path "DC=techcorp,DC=local"
New-ADOrganizationalUnit -Name "Finance"    -Path "DC=techcorp,DC=local"
New-ADOrganizationalUnit -Name "Sales"      -Path "DC=techcorp,DC=local"
New-ADOrganizationalUnit -Name "Marketing"  -Path "DC=techcorp,DC=local"
New-ADOrganizationalUnit -Name "Operations" -Path "DC=techcorp,DC=local"
```

### Create realistic company users

```powershell
# ── IT Department ──────────────────────────────────────
New-ADUser -Name "Mian Awais" `
  -GivenName "Mian" -Surname "Awais" `
  -SamAccountName "mianawais" `
  -UserPrincipalName "mianawais@techcorp.local" `
  -Path "OU=IT,DC=techcorp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "SOCAnalyst@2026" -AsPlainText -Force) `
  -Enabled $true -Department "IT" -Title "SOC Analyst" `
  -OfficePhone "0300-1111111"

New-ADUser -Name "Hamza Khan" `
  -GivenName "Hamza" -Surname "Khan" `
  -SamAccountName "hamza" `
  -UserPrincipalName "hamza@techcorp.local" `
  -Path "OU=IT,DC=techcorp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "SysAdmin@2026" -AsPlainText -Force) `
  -Enabled $true -Department "IT" -Title "System Administrator" `
  -OfficePhone "0300-1111222"

New-ADUser -Name "Awais Javed" `
  -GivenName "Awais" -Surname "Javed" `
  -SamAccountName "awais" `
  -UserPrincipalName "awais@techcorp.local" `
  -Path "OU=IT,DC=techcorp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) `
  -Enabled $true -Department "IT" -Title "Network Engineer"

New-ADUser -Name "Sara Ahmad" `
  -GivenName "Sara" -Surname "Ahmad" `
  -SamAccountName "sara" `
  -UserPrincipalName "sara@techcorp.local" `
  -Path "OU=IT,DC=techcorp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Welcome1" -AsPlainText -Force) `
  -Enabled $true -Department "IT" -Title "IT Helpdesk"

# ── HR Department ───────────────────────────────────────
New-ADUser -Name "Ayesha Khan" `
  -GivenName "Ayesha" -Surname "Khan" `
  -SamAccountName "ayeshak" `
  -UserPrincipalName "ayeshak@techcorp.local" `
  -Path "OU=HR,DC=techcorp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
  -Enabled $true -Department "HR" -Title "HR Manager" `
  -OfficePhone "0300-2222111"

New-ADUser -Name "Usman Ali" `
  -GivenName "Usman" -Surname "Ali" `
  -SamAccountName "usman" `
  -UserPrincipalName "usman@techcorp.local" `
  -Path "OU=HR,DC=techcorp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
  -Enabled $true -Department "HR" -Title "HR Executive"

# ── Finance Department ──────────────────────────────────
New-ADUser -Name "Fatima Ahmed" `
  -GivenName "Fatima" -Surname "Ahmed" `
  -SamAccountName "fatima" `
  -UserPrincipalName "fatima@techcorp.local" `
  -Path "OU=Finance,DC=techcorp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
  -Enabled $true -Department "Finance" -Title "Finance Manager" `
  -OfficePhone "0300-3333111"

New-ADUser -Name "Bilal Hassan" `
  -GivenName "Bilal" -Surname "Hassan" `
  -SamAccountName "bilal" `
  -UserPrincipalName "bilal@techcorp.local" `
  -Path "OU=Finance,DC=techcorp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
  -Enabled $true -Department "Finance" -Title "Accountant"

# ── Sales Department ────────────────────────────────────
New-ADUser -Name "Sana Malik" `
  -GivenName "Sana" -Surname "Malik" `
  -SamAccountName "sana" `
  -UserPrincipalName "sana@techcorp.local" `
  -Path "OU=Sales,DC=techcorp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
  -Enabled $true -Department "Sales" -Title "Sales Manager"

New-ADUser -Name "Ali Raza" `
  -GivenName "Ali" -Surname "Raza" `
  -SamAccountName "aliraza" `
  -UserPrincipalName "aliraza@techcorp.local" `
  -Path "OU=Sales,DC=techcorp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
  -Enabled $true -Department "Sales" -Title "Sales Executive"

# ── Marketing Department ────────────────────────────────
New-ADUser -Name "Zara Sheikh" `
  -GivenName "Zara" -Surname "Sheikh" `
  -SamAccountName "zara" `
  -UserPrincipalName "zara@techcorp.local" `
  -Path "OU=Marketing,DC=techcorp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
  -Enabled $true -Department "Marketing" -Title "Marketing Manager"

# ── Operations Department ───────────────────────────────
New-ADUser -Name "Omar Farooq" `
  -GivenName "Omar" -Surname "Farooq" `
  -SamAccountName "omar" `
  -UserPrincipalName "omar@techcorp.local" `
  -Path "OU=Operations,DC=techcorp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
  -Enabled $true -Department "Operations" -Title "Operations Manager"
```

```powershell
# Verify the users were created
Get-ADUser -Filter * -Properties Department, Title |
  Select Name, SamAccountName, Department, Title |
  Format-Table -AutoSize

# Count them
(Get-ADUser -Filter *).Count
```

### On Kali — install the LDAP tools

```bash
# Update packages and install LDAP client utilities
sudo apt update
sudo apt install ldap-utils -y

# Confirm the install
ldapsearch --version

# Tools for scanning and follow-up attacks
sudo apt install nmap hydra -y
```

### Nmap — fingerprint the Domain Controller

```bash
# Quick open-port sweep of the DC
nmap 192.168.100.110

# Full service/version/OS detection (slow but thorough)
nmap -sV -sC -p- 192.168.100.110

# Targeted scan of AD-related ports only
nmap -sV -p 53,88,135,139,389,445,464,636,3268,3269,3389 192.168.100.110
```

Expected result on a real DC:

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        DNS
88/tcp   open  kerberos-sec  Kerberos
135/tcp  open  msrpc         Microsoft RPC
139/tcp  open  netbios-ssn   NetBIOS
389/tcp  open  ldap          Microsoft AD LDAP
445/tcp  open  microsoft-ds  SMB
464/tcp  open  kpasswd5      Kerberos password change
636/tcp  open  tcpwrapped    LDAPS (encrypted)
3268/tcp open  ldap          Global Catalog
3269/tcp open  tcpwrapped    Global Catalog SSL
3389/tcp open  ms-wbt-server RDP
```

What each open port tells an attacker:

| Port | Service | Attacker reads it as |
|------|---------|----------------------|
| 389 | LDAP | Directory enumeration possible |
| 88 | Kerberos | Kerberoasting attacks possible |
| 445 | SMB | Share enumeration possible |
| 3389 | RDP | RDP brute force possible |
| 53 | DNS | Domain name confirmed |

### LDAP enumeration from Kali

```bash
# 1. Test anonymous bind (no credentials)
ldapsearch -x -H ldap://192.168.100.110 \
  -b "dc=techcorp,dc=local" \
  "(objectClass=*)" 2>/dev/null | head -20
```
> If this returns data, anonymous bind is allowed — a **critical misconfiguration**. In my lab it errored out: anonymous bind is correctly blocked.

```bash
# 2. Authenticated bind — dump the entire directory with one valid account
ldapsearch -x -H ldap://192.168.100.110 \
  -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" \
  "(objectclass=*)"
# Enter the account password when prompted
```

```bash
# 3. Save the dump and measure it
ldapsearch -x -H ldap://192.168.100.110 \
  -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" \
  "(objectclass=*)" > full_dump.txt

wc -l full_dump.txt              # how many lines of directory data
grep "dn:" full_dump.txt | wc -l # how many objects were returned
```

### Targeted LDAP queries (the attacker shortlist)

```bash
# Q1 — every user with useful attributes
ldapsearch -x -H ldap://192.168.100.110 -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" "(objectClass=user)" \
  sAMAccountName displayName department title userPrincipalName

# Q2 — one user's full record
ldapsearch -x -H ldap://192.168.100.110 -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" "(sAMAccountName=fatima)"

# Q3 — everyone in the IT department
ldapsearch -x -H ldap://192.168.100.110 -D "awais@techcorp.local" -W \
  -b "OU=IT,DC=techcorp,DC=local" "(objectClass=user)" \
  sAMAccountName displayName title

# Q4 — who are the Domain Admins? (privilege-escalation targeting)
ldapsearch -x -H ldap://192.168.100.110 -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" \
  "(memberOf=CN=Domain Admins,CN=Users,DC=techcorp,DC=local)" \
  sAMAccountName displayName

# Q5 — accounts whose password was never set (pwdLastSet=0)
ldapsearch -x -H ldap://192.168.100.110 -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" "(&(objectClass=user)(pwdLastSet=0))" \
  sAMAccountName displayName

# Q6 — accounts where the password never expires (bit 65536 in userAccountControl)
ldapsearch -x -H ldap://192.168.100.110 -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" \
  sAMAccountName displayName

# Q7 — list all groups and their members
ldapsearch -x -H ldap://192.168.100.110 -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" "(objectClass=group)" cn member

# Q8 — list all departments (OUs)
ldapsearch -x -H ldap://192.168.100.110 -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" "(objectClass=organizationalUnit)" ou

# Q9 — read the domain password policy
ldapsearch -x -H ldap://192.168.100.110 -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" "(objectClass=domain)" \
  minPwdLength lockoutThreshold maxPwdAge pwdHistoryLength

# Q10 — find Service Principal Names (Kerberoasting preparation)
ldapsearch -x -H ldap://192.168.100.110 -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" "(&(objectClass=user)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName
```

---
## 🔍 Wireshark Analysis

Start the capture on Kali **before** running `ldapsearch`:

```bash
# GUI capture
sudo wireshark &

# or headless capture to a file
sudo tcpdump -i eth0 -w ldap_capture.pcap port 389
```

**Display filters:**

```
ldap
```
> All LDAP traffic.

```
tcp.port == 389
```
> Everything on the LDAP port (includes TCP handshake around it).

```
ip.addr == 192.168.100.110 && ldap
```
> Only LDAP traffic to/from the Domain Controller.

### What the packets show

```
Packet 1:   TCP SYN  (Kali → DC)              — connection starts
Packet 2:   TCP SYN-ACK (DC → Kali)          — connection accepted
Packet 3:   LDAP bindRequest                 — your username + password
Packet 4:   LDAP bindResponse                — success or failure
Packet 5:   LDAP searchRequest               — your query
Packet 6-N: LDAP searchResEntry × many       — user data returned
Packet N+1: LDAP unbindRequest               — disconnect
```

> 🔑 Key observation from my capture: LDAP on port 389 is **plaintext** — the bind request shows the username and password in cleartext, and every search result comes back readable. This is why production must use LDAPS (port 636).

### What the data revealed

From **one** `ldapsearch` with **one** valid user credential, an attacker learns the whole company:

| Username | Full Name | Department | Title | Attacker value |
|----------|-----------|------------|-------|----------------|
| `awais` | Awais Javed | IT | Network Engineer | Initial access account |
| `mianawais` | Mian Awais | IT | SOC Analyst | Security team member |
| `hamza` | Hamza Khan | IT | Sysadmin | High-privilege target |
| `sara` | Sara Ahmad | IT | IT Helpdesk | Weak password (`Welcome1`) |
| `ayeshak` | Ayesha Khan | HR | HR Manager | Employee data access |
| `fatima` | Fatima Ahmed | Finance | Finance Manager | **Critical target** (wire fraud) |
| `bilal` | Bilal Hassan | Finance | Accountant | Financial data access |
| `sana` | Sana Malik | Sales | Sales Manager | CRM access |

### Security findings from the dump

| Finding | Severity | Detail |
|---------|----------|--------|
| No account lockout threshold | **Critical** | Brute force possible without lockout |
| `sara` — `pwdLastSet=0` | **Critical** | Password never properly set |
| Weak password policy | High | Minimum length 7, no complexity enforced |
| Administrator password never expires | High | Long-term credential exposure |
| Authenticated enumeration allowed | Medium | Any domain user can read all AD objects |

---
## 🚨 SOC Analyst Notes

### How this happens in real life

Port 389 is **not** exposed to the internet in a real company — it's behind the firewall. So how do real attackers reach it?

**Phase 1 — Initial access (getting inside):**
- **Phishing email** → employee clicks → credentials stolen → attacker gets VPN access
- **Password spray on VPN/OWA** → public login page + common passwords (`Password123`, `Welcome1`) + no lockout = thousands of free guesses
- **Exposed RDP** → attacker finds it on Shodan/Censys and brute-forces it
- **Third-party breach** → employee reused a breached LinkedIn password on the VPN

**Phase 2 — Inside the network (this lab's scenario):** once the attacker has VPN access, the internal `192.168.x.x` range — and LDAP port 389 — is reachable. Every `ldapsearch` command in this lab now works against the real company.

**Phase 3 — Lateral movement:** from the LDAP dump the attacker knows who the Finance Manager is (wire-fraud target), who the sysadmin is (privilege-escalation target), what the password policy allows, and which groups lead to Domain Admin.

**Phase 4 — Impact:** ransomware, data theft, financial fraud.

> Attackers find exposed servers with Shodan queries like `port:389 country:PK` or `port:3389 country:PK` — which is why these ports must **never** face the internet.

### My lab vs a real-world attack

| Aspect | My lab | Real company attack |
|--------|--------|---------------------|
| Network | Same LAN (`192.168.x.x`) | VPN → internal LAN |
| Credential source | I set them myself | Phishing / password spray |
| LDAP access | Direct on the LAN | After VPN access or breach |
| Purpose | Learning | Malicious |
| Detection | Optional | Should be monitored 24/7 |

### Windows Event IDs to monitor

| Event ID | Meaning | Triggered by |
|----------|---------|--------------|
| 4624 | Successful logon | LDAP bind success |
| 4625 | Failed logon | LDAP bind failure / brute force |
| 4776 | Credential validation | Any authentication attempt |
| 4740 | Account locked out | Brute force tripping lockout |
| 4662 | Directory object access | LDAP directory enumeration |
| 4728 | Member added to group | Privilege escalation |

### Example SIEM detection rule

```
IF   same source IP makes > 50 LDAP queries in 60 seconds
AND  the queries span multiple OUs
THEN alert "Possible AD Enumeration" — Severity: HIGH
```

### Defensive recommendations

1. Enable account lockout (threshold: 5 attempts)
2. Enforce password complexity (minimum 12 characters)
3. Block LDAP port 389 from all non-admin workstations
4. Use **LDAPS (port 636)** — encrypted LDAP everywhere
5. Enforce MFA on all accounts
6. Monitor Event ID **4662** for bulk directory reads
7. Never expose RDP or LDAP to the internet
8. Use privileged access workstations for admin tasks

---
## 🛡️ MITRE ATT&CK

| Technique | ID | Relevance |
|-----------|----|-----------|
| Remote System Discovery | T1018 | Scanning for the DC and LDAP on 389 |
| Account Discovery: Domain Account | T1087.002 | Dumping users, groups, OUs via `ldapsearch` |
| Brute Force | T1110 | Password guessing against LDAP binds |
| Valid Accounts | T1078 | One compromised domain account enumerates everything |
| Steal or Forge Kerberos Tickets | T1558 | SPN enumeration (Query 10) as Kerberoasting prep |

---
## 📸 Screenshots

| Screenshot | Description |
|------------|-------------|
| ![Full LDAP dump](LDAP%20%281%29.jpeg) | Kali terminal — `ldapsearch` full directory dump saved to `full_dump.txt`, then counting lines and objects with `wc -l` and `grep "dn:"` |
| ![Bind request in Wireshark](LDAP%20%282%29.jpeg) | Wireshark packet detail — LDAP bindRequest from `192.168.100.90` to the DC, username and password visible in cleartext |
| ![LDAP session in Wireshark](LDAP%20%283%29.jpeg) | Wireshark packet list — full session: `bindRequest` → `bindResponse(success)` → `searchRequest` → `searchResEntry` results (`CN=Administrator`, `CN=Guest`, `CN=Sara Ahmad`) → `unbindRequest` |

---
## ✅ Key Takeaways

```
════════════════════════════════════════════════════════
             LDAP ENUMERATION — FINDINGS REPORT
         Domain: techcorp.local | Date: May 2026
════════════════════════════════════════════════════════

TARGET INFORMATION
  Domain Controller : WIN-N4LQQSU0MFA.techcorp.local
  IP Address        : 192.168.100.110
  OS                : Windows Server 2022 Standard
  Domain Level      : Windows Server 2016+ (Level 7)

USERS DISCOVERED    : 12
DEPARTMENTS FOUND   : 6 (IT, HR, Finance, Sales, Marketing, Operations)
GROUPS FOUND        : 30+

CRITICAL FINDINGS
  [CRIT] No account lockout threshold — brute force possible
  [CRIT] User 'sara' — pwdLastSet=0 (password not properly set)
  [HIGH] Minimum password length = 7 (too short)
  [HIGH] Administrator password never expires
  [MED]  Any authenticated user can enumerate full AD

ATTACK PATH IDENTIFIED
  1. Obtain one valid credential (any domain user)
  2. Run ldapsearch → dump the entire company directory
  3. Identify high-value targets (Finance Manager, Sysadmin)
  4. Password-spray the weak accounts
  5. Escalate to Domain Admin

TOOLS USED
  nmap, ldapsearch (ldap-utils), hydra, Wireshark, Kali Linux
════════════════════════════════════════════════════════
```

**Bottom line:** I built the domain, populated it, enumerated it with a single low-privilege account, watched the credentials cross the wire in cleartext, and documented every finding — the full attacker *and* defender view of LDAP.

---
## 📣 LinkedIn Post (draft)

> 🛡️ I just finished a full Active Directory & LDAP enumeration lab! Built a Windows Server 2022 domain (techcorp.local) with 12 users across 6 departments, then enumerated the entire directory from Kali with ldapsearch — and captured it all in Wireshark. Key lesson: LDAP on port 389 is plaintext, and one valid account is enough to map a whole company. Full write-up in my SOC-Journey-2026 repo. #BlueTeam #SOCAnalyst #ActiveDirectory #CyberSecurity
