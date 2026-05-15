
# 🔐 Lab  — Windows Active Directory & LDAP Enumeration
### SOC Analyst Practical Lab | TechCorp Domain | May 2026

> **Author:** Muhammad Awais Javed  — SOC Analyst in Training  
> **Domain:** techcorp.local | **DC IP:** 192.168.100.110  
> **Attacker Machine:** Kali Linux | **Target:** Windows Server 2022

---

## 📌 Table of Contents

1. [What is LDAP?](#what-is-ldap)
2. [How LDAP Works](#how-ldap-works)
3. [What is Active Directory?](#what-is-active-directory)
4. [Lab Environment Setup](#lab-environment-setup)
5. [Windows Server — Domain Setup](#windows-server--domain-setup)
6. [Creating OUs and Users (PowerShell)](#creating-ous-and-users-powershell)
7. [Kali Linux — LDAP Tools Installation](#kali-linux--ldap-tools-installation)
8. [Nmap — Port Scanning the DC](#nmap--port-scanning-the-dc)
9. [LDAP Enumeration from Kali](#ldap-enumeration-from-kali)
10. [Targeted LDAP Queries](#targeted-ldap-queries)
11. [What the Data Reveals](#what-the-data-reveals)
12. [How Attackers Do This in Real Life](#how-attackers-do-this-in-real-life)
13. [SOC Detection & Defense](#soc-detection--defense)
14. [Wireshark Analysis](#wireshark-analysis)
15. [Key Findings Summary](#key-findings-summary)
16. [LinkedIn Post](#linkedin-post)

---

## What is LDAP?

**LDAP (Lightweight Directory Access Protocol)** is a protocol used to access and manage directory information over a network. Think of it as a **phone book for a company network** — it stores information about users, computers, groups, departments, and permissions.

- **Port:** 389 (plain) | 636 (LDAPS — encrypted)
- **Protocol Type:** TCP
- **Used by:** Active Directory, OpenLDAP, email clients, HR systems, VPNs

Every time an employee logs into their work laptop, their computer is talking LDAP in the background — asking the server "is this password correct?"

### LDAP Structure (DN — Distinguished Name)

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
| `DC` | Domain Component (techcorp, local) |
| `OU` | Organizational Unit (department) |
| `CN` | Common Name (user/group name) |
| `DN` | Distinguished Name (full path to object) |

---

## How LDAP Works

```
[ Kali Linux / Attacker ]                [ Windows Server DC ]
         |                                        |
         |--- 1. TCP Connect to port 389 -------> |
         |                                        |
         |--- 2. BIND Request (username+pass) --> |
         |                                        |
         |<-- 3. BIND Response (success/fail) --- |
         |                                        |
         |--- 4. SEARCH Request (query) --------> |
         |                                        |
         |<-- 5. SEARCH Results (user data) ----- |
         |                                        |
         |--- 6. UNBIND (disconnect) -----------> |
```

The **BIND** operation is authentication. Once you bind successfully with any valid user account, you can search the entire directory — because AD is designed for employees to look up colleagues.

---

## What is Active Directory?

**Active Directory (AD)** is Microsoft's implementation of LDAP. It is the central identity and access management system used in almost every medium-to-large company worldwide.

**What AD stores:**
- All user accounts (name, email, phone, department, title)
- All computer accounts
- All groups and their members
- Password policies
- Access permissions (who can access what folder/system)

**Real-world analogy:** AD is the company's HR database + security guard + phone book, all in one.

**Why SOC analysts care:** When attackers get inside a network, the first thing they do is enumerate AD using LDAP. Understanding this is core to detecting and stopping them.

---

## Lab Environment Setup

```
┌─────────────────────────────────────────────────────┐
│                   HOME LAB NETWORK                   │
│                  192.168.100.0/24                    │
│                                                      │
│  ┌──────────────────────┐   ┌─────────────────────┐ │
│  │   Windows Server VM  │   │    Kali Linux        │ │
│  │   (Domain Controller)│   │    (Attacker)        │ │
│  │   IP: 192.168.100.110│   │    IP: 192.168.100.90 │ │
│  │   OS: Win Server 2022│   │    Tool: ldapsearch  │ │
│  │   Domain: techcorp   │   │    Tool: nmap        │ │
│  │   Role: AD DS        │   │    Tool: hydra       │ │
│  └──────────────────────┘   └─────────────────────┘ │
│                                                      │
│              Both on same VMware/VirtualBox NAT      │
└─────────────────────────────────────────────────────┘
```

**Prerequisites:**
- VMware Workstation or VirtualBox
- Windows Server 2022 ISO (Evaluation — free from Microsoft)
- Kali Linux ISO
- Both VMs on same network adapter (NAT or Host-Only)

---

## Windows Server — Domain Setup

### Step 1: Install Active Directory Domain Services

Open PowerShell as Administrator on Windows Server:

```powershell
# Install AD DS role
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

# Promote server to Domain Controller
Install-ADDSForest `
  -DomainName "techcorp.local" `
  -DomainNetbiosName "TECHCORP" `
  -InstallDns:$true `
  -Force:$true
```

Server will restart automatically after promotion.

### Step 2: Verify Domain is Running

```powershell
# Check AD DS service
Get-Service ADWS, NTDS, DNS, Netlogon

# Verify domain
Get-ADDomain
```

---

## Creating OUs and Users (PowerShell)

### Step 3: Create Departments (Organizational Units)

```powershell
# Create all department OUs
New-ADOrganizationalUnit -Name "IT"         -Path "DC=techcorp,DC=local"
New-ADOrganizationalUnit -Name "HR"         -Path "DC=techcorp,DC=local"
New-ADOrganizationalUnit -Name "Finance"    -Path "DC=techcorp,DC=local"
New-ADOrganizationalUnit -Name "Sales"      -Path "DC=techcorp,DC=local"
New-ADOrganizationalUnit -Name "Marketing"  -Path "DC=techcorp,DC=local"
New-ADOrganizationalUnit -Name "Operations" -Path "DC=techcorp,DC=local"
```

### Step 4: Create Realistic Company Users

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

### Step 5: Verify Users Were Created

```powershell
# List all users in domain
Get-ADUser -Filter * -Properties Department, Title | 
  Select Name, SamAccountName, Department, Title | 
  Format-Table -AutoSize

# Count total users
(Get-ADUser -Filter *).Count
```

---

## Kali Linux — LDAP Tools Installation

```bash
# Update package list
sudo apt update

# Install LDAP utilities
sudo apt install ldap-utils -y

# Verify installation
ldapsearch --version

# Install additional tools
sudo apt install nmap hydra -y
```

---

## Nmap — Port Scanning the DC

Before LDAP enumeration, a real attacker (and SOC analyst) scans for open ports.

### Basic scan:

```bash
nmap 192.168.100.110
```

### Full service version scan:

```bash
nmap -sV -sC -p- 192.168.100.110
```

### Scan specifically for AD-related ports:

```bash
nmap -sV -p 53,88,135,139,389,445,464,636,3268,3269,3389 192.168.100.110
```

### Expected output for a Domain Controller:

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

### What each port tells an attacker:

| Port | Service | What it means |
|------|---------|---------------|
| 389 | LDAP | Directory enumeration possible |
| 88 | Kerberos | Kerberoasting attacks possible |
| 445 | SMB | File share enumeration possible |
| 3389 | RDP | Remote desktop brute force possible |
| 53 | DNS | Domain name confirmed |

---

## LDAP Enumeration from Kali

### Step 1: Test anonymous bind (unauthenticated)

```bash
ldapsearch -x -H ldap://192.168.100.110 \
  -b "dc=techcorp,dc=local" \
  "(objectClass=*)" 2>/dev/null | head -20
```

If this returns data — **critical misconfiguration** (anonymous bind allowed).  
In our lab it returns error — anonymous bind is blocked (correct security posture).

### Step 2: Authenticated bind — dump everything

```bash
ldapsearch -x -H ldap://192.168.100.110 \
  -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" \
  "(objectclass=*)"
```

Enter password when prompted. This dumps the **entire AD database**.

### Step 3: Save output to file for analysis

```bash
ldapsearch -x -H ldap://192.168.100.110 \
  -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" \
  "(objectclass=*)" > full_dump.txt

wc -l full_dump.txt    # count lines
grep "dn:" full_dump.txt | wc -l   # count objects
```

---

## Targeted LDAP Queries

### Query 1: Get all users with key attributes

```bash
ldapsearch -x -H ldap://192.168.100.110 \
  -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" \
  "(objectClass=user)" \
  sAMAccountName displayName department title userPrincipalName
```

### Query 2: Get single user's full details

```bash
ldapsearch -x -H ldap://192.168.100.110 \
  -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" \
  "(sAMAccountName=fatima)"
```

### Query 3: Get all users in IT department

```bash
ldapsearch -x -H ldap://192.168.100.110 \
  -D "awais@techcorp.local" -W \
  -b "OU=IT,DC=techcorp,DC=local" \
  "(objectClass=user)" \
  sAMAccountName displayName title
```

### Query 4: Find all Domain Admins

```bash
ldapsearch -x -H ldap://192.168.100.110 \
  -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" \
  "(memberOf=CN=Domain Admins,CN=Users,DC=techcorp,DC=local)" \
  sAMAccountName displayName
```

### Query 5: Find accounts with password never set

```bash
ldapsearch -x -H ldap://192.168.100.110 \
  -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" \
  "(&(objectClass=user)(pwdLastSet=0))" \
  sAMAccountName displayName
```

### Query 6: Find accounts where password never expires

```bash
ldapsearch -x -H ldap://192.168.100.110 \
  -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" \
  sAMAccountName displayName
```

### Query 7: List all groups

```bash
ldapsearch -x -H ldap://192.168.100.110 \
  -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" \
  "(objectClass=group)" \
  cn member
```

### Query 8: List all OUs (departments)

```bash
ldapsearch -x -H ldap://192.168.100.110 \
  -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" \
  "(objectClass=organizationalUnit)" \
  ou
```

### Query 9: Get password policy

```bash
ldapsearch -x -H ldap://192.168.100.110 \
  -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" \
  "(objectClass=domain)" \
  minPwdLength lockoutThreshold maxPwdAge pwdHistoryLength
```

### Query 10: Find Service Principal Names (SPNs) — Kerberoasting prep

```bash
ldapsearch -x -H ldap://192.168.100.110 \
  -D "awais@techcorp.local" -W \
  -b "dc=techcorp,dc=local" \
  "(&(objectClass=user)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName
```

---

## What the Data Reveals

From a single ldapsearch with one valid user credential, an attacker learns:

### Users Discovered:

| Username | Full Name | Department | Title | Risk |
|----------|-----------|------------|-------|------|
| `awais` | Awais Javed | IT | Network Engineer | Used for initial access |
| `mianawais` | Mian Awais | IT | SOC Analyst | Security team member |
| `hamza` | Hamza Khan | IT | Sysadmin | High privilege target |
| `sara` | Sara Ahmad | IT | IT Helpdesk | Weak/no password |
| `ayeshak` | Ayesha Khan | HR | HR Manager | Employee data access |
| `fatima` | Fatima Ahmed | Finance | Finance Manager | **Critical target** |
| `bilal` | Bilal Hassan | Finance | Accountant | Financial data access |
| `sana` | Sana Malik | Sales | Sales Manager | CRM access |

### Security Findings:

| Finding | Severity | Detail |
|---------|----------|--------|
| Authenticated LDAP enumeration allowed | Medium | Any domain user can read all AD objects |
| No lockout threshold | **Critical** | Brute force possible without lockout |
| Weak password policy | High | Min length 7, no complexity enforced |
| `sara` — pwdLastSet=0 | **Critical** | Password never properly set |
| Administrator password never expires | High | Long-term credential exposure |

---

## How Attackers Do This in Real Life

### The Reality: LDAP Port 389 is NOT exposed to the internet

In a real company, port 389 is behind a firewall. You cannot just run ldapsearch from your home against a company's server.

**So how do real attackers get in?**

### Attack Chain — External to Internal:

```
Phase 1: Initial Access (Getting Inside)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Method 1 — Phishing Email
  Attacker sends fake email to employee (e.g., sara@techcorp.com)
  Employee clicks link → credentials stolen
  Now attacker has sara's VPN password

Method 2 — Password Spray on VPN/OWA
  Attacker finds company's VPN login page (public)
  Tries common passwords: Password123, Welcome1, Company@2024
  No lockout policy → tries thousands without getting blocked

Method 3 — Exposed RDP (Port 3389 on internet)
  Attacker scans internet with Shodan/Censys
  Finds company's RDP exposed
  Brute forces RDP credentials

Method 4 — Third-party breach
  Employee reused their LinkedIn password
  LinkedIn got breached → attacker tries same password on VPN

Phase 2: Inside the Network (Your Lab Scenario)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Once attacker has VPN access, they are "inside"
Now 192.168.x.x range is accessible
Now LDAP port 389 is reachable
Now your exact ldapsearch commands work against the real company

Phase 3: Lateral Movement
━━━━━━━━━━━━━━━━━━━━━━━━
From LDAP dump attacker knows:
  - Who is the Finance Manager (fatima) → target for wire fraud
  - Who is the Sysadmin (hamza) → target for privilege escalation
  - Password policy → plan brute force accordingly
  - Groups → find path to Domain Admin

Phase 4: Impact
━━━━━━━━━━━━━━
Ransomware deployment, data exfiltration, financial fraud
```

### Shodan — How attackers find targets:

Real attackers use `shodan.io` to search:
```
port:389 country:PK org:"Company Name"
port:3389 country:PK
```
This shows every exposed LDAP or RDP server in Pakistan. This is why companies must **never** expose these ports directly to the internet.

### Your Lab vs Real World:

| Aspect | Your Lab | Real Company Attack |
|--------|----------|---------------------|
| Network | Same LAN (192.168.x.x) | VPN → Internal LAN |
| Credential source | You set them | Phishing / password spray |
| LDAP access | Direct | After VPN or breach |
| Purpose | Learning | Malicious |
| Detection | Optional | Should be monitored 24/7 |

---

## SOC Detection & Defense

### Windows Event IDs to Monitor:

| Event ID | Meaning | Triggered by |
|----------|---------|--------------|
| 4624 | Successful logon | LDAP bind success |
| 4625 | Failed logon | LDAP bind failure / brute force |
| 4776 | Credential validation | Any authentication attempt |
| 4740 | Account locked out | Brute force detected |
| 4662 | Object access | LDAP directory enumeration |
| 4728 | Member added to group | Privilege escalation |

### Detection Rule (SIEM logic):

```
IF same source IP makes > 50 LDAP queries in 60 seconds
AND queries span multiple OUs
THEN alert: "Possible AD Enumeration"
Severity: HIGH
```

### Defensive Recommendations:

```
1. Enable account lockout (threshold: 5 attempts)
2. Enforce password complexity (min 12 chars)
3. Block LDAP port 389 from all non-admin workstations
4. Use LDAPS (port 636) — encrypted LDAP
5. Implement MFA on all accounts
6. Monitor Event ID 4662 for bulk directory reads
7. Never expose RDP/LDAP to internet
8. Use privileged access workstations for admin tasks
```

---

## Wireshark Analysis

### How to capture LDAP traffic:

On Kali Linux, start Wireshark before running ldapsearch:

```bash
# Start capture on your network interface
sudo wireshark &

# Or use tcpdump to capture to file
sudo tcpdump -i eth0 -w ldap_capture.pcap port 389
```

### Wireshark filter for LDAP:

```
ldap
tcp.port == 389
ip.addr == 192.168.100.110 && ldap
```

### What you will see in Wireshark:

```
Packet 1: TCP SYN (Kali → DC) — connection start
Packet 2: TCP SYN-ACK (DC → Kali) — connection accepted
Packet 3: LDAPMessage bindRequest — your username/password
Packet 4: LDAPMessage bindResponse — success/failure
Packet 5: LDAPMessage searchRequest — your query
Packet 6-N: LDAPMessage searchResEntry — user data returned
Packet N+1: LDAPMessage unbindRequest — disconnect
```

### Key observation:

LDAP on port 389 is **plaintext** — Wireshark shows your username, search queries, and all returned data in clear text. This is why LDAPS (port 636) should always be used instead.

---

## Key Findings Summary

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
DEPARTMENTS FOUND   : 6 (IT, HR, Finance, Sales, Marketing, Ops)
GROUPS FOUND        : 30+

CRITICAL FINDINGS
  [CRIT] No account lockout threshold — brute force possible
  [CRIT] User 'sara' — pwdLastSet=0 (password not properly set)
  [HIGH] Minimum password length = 7 (too short)
  [HIGH] Administrator password never expires
  [MED]  Any authenticated user can enumerate full AD

ATTACK PATH IDENTIFIED
  1. Obtain one valid credential (awais / any user)
  2. Run ldapsearch → dump entire company directory
  3. Identify high-value targets (Finance Manager, Sysadmin)
  4. Use password spray against weak accounts
  5. Escalate to Domain Admin

TOOLS USED
  nmap, ldapsearch (ldap-utils), Wireshark, Kali Linux
════════════════════════════════════════════════════════
```

---



#CyberSecurity #SOCAnalyst #ActiveDirectory #LDAP #EthicalHacking 
#PenTesting #BlueTeam #RedTeam #HomeLab #SecurityAnalyst #Pakistan 
#CyberSecurityPakistan #InfoSec #NetworkSecurity
```

---
