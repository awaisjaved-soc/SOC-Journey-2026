# 🔐 SSH & SFTP — Port 22 | Practical Lab

**Author:** Muhammad Awais Javed (Mian Awais) / **Date:** April 2026 / **Part of:** [SOC-Journey-2026](https://github.com/awaisjaved-soc/SOC-Journey-2026)

---

## 📌 Table of Contents

- [🎯 Objective](#-objective)
- [📖 What is SSH?](#-what-is-ssh)
- [⚙️ How It Works](#️-how-it-works)
- [🧪 Lab Environment](#-lab-environment)
- [💻 Commands Used](#-commands-used)
- [🛡️ Fail2Ban — SSH Brute-Force Protection](#️-fail2ban--ssh-brute-force-protection)
- [🔍 Wireshark Analysis](#-wireshark-analysis)
- [🚨 SOC Analyst Notes](#-soc-analyst-notes)
- [🛡️ MITRE ATT&CK](#️-mitre-attck)
- [📸 Screenshots](#-screenshots)
- [✅ Key Takeaways](#-key-takeaways)

---

## 🎯 Objective

To set up a real SSH server on a Linux laptop, connect to it from a Kali VM, transfer files over the encrypted channel (SCP/SFTP), watch the handshake in Wireshark — and then defend the whole thing by deploying **Fail2Ban** against a live brute-force simulation.

This lab has two parts, each in its own folder:

| Part | Folder |
|------|--------|
| SSH server setup, client connections, SCP/SFTP file transfers | [`SSH-practice-and-captures`](./SSH-practice-and-captures/) |
| Fail2Ban install, custom jail, brute-force simulation, banning | [`fail2ban-commands`](./fail2ban-commands/) |

---

## 📖 What is SSH?

**SSH (Secure Shell)** is a cryptographic network protocol for securely operating network services over an unsecured network. It runs on **TCP port 22** and replaces the old plaintext remote-access tools (Telnet, FTP, rlogin).

### SSH vs FTP — why it matters

| | FTP | SSH (ssh / scp / sftp) |
|---|---|---|
| Ports | 21 (control) + 20 (data) | **22 only** |
| Encryption | ❌ None — credentials and files in plaintext | ✅ Everything encrypted |
| Login | `ftp <ip>` then username/password | `ssh user@<ip>` |
| File transfer | `put` / `get` (plaintext) | `scp` / `sftp` (encrypted) |

### The tools in this lab

- **`ssh`** — opens an encrypted remote shell on the server.
- **`scp`** — securely copies files between machines (one-shot, like encrypted `cp`).
- **`sftp`** — interactive file-transfer session over SSH (like FTP, but encrypted: `ls`, `cd`, `get`, `put`).

---

## ⚙️ How It Works

Every SSH connection — whether `ssh`, `scp`, or `sftp` — runs the same handshake:

1. **Version exchange** — client and server announce their SSH protocol versions (plaintext, visible in Wireshark).
2. **Key exchange (KEX)** — both sides agree on encryption algorithms and derive session keys (Diffie-Hellman). From here on, everything is encrypted.
3. **Server authentication** — the client verifies the server's host key (this is the `The authenticity of host can't be established` prompt).
4. **Client authentication** — password or public-key authentication.
5. **Encrypted session** — shell, file transfer, or port forwarding inside the secure tunnel.

> In Wireshark you can read step 1 clearly, then watch the traffic turn into an opaque encrypted stream — that visible "before/after" moment is exactly what I captured in this lab.

---

## 🧪 Lab Environment

| Role | Machine | Details |
|------|---------|---------|
| SSH Server | Linux laptop | OpenSSH server, UFW firewall, Fail2Ban |
| SSH Client / Attacker | Kali VM | `ssh`, `scp`, `sftp`, `nmap`, `nc` |
| Protocol | TCP port 22 | LAN connectivity between the two |

---

## 💻 Commands Used

> In the original lab notes the server IP is written as `ip` — substitute your server's actual IP (find it with `ip addr show`).

### Section 1 — SSH server setup (on the Linux laptop)

```bash
sudo apt update && sudo apt install openssh-server -y
```
Installs the OpenSSH server package — this turns the laptop into an SSH server listening on port 22.

```bash
sudo systemctl enable --now ssh
```
Starts the SSH service now and enables it on every boot.

```bash
sudo systemctl status ssh
```
Verifies the service is `Active: active (running)` — the daily SOC health check.

```bash
sudo ss -tlnp | grep :22
```
Confirms SSH is really listening on port 22 (expect `0.0.0.0:22`).

```bash
sudo ufw allow ssh
```
Opens port 22 in the firewall — without this, connections are blocked.

```bash
sudo ufw enable
```
Activates UFW so the rules take effect.

```bash
sudo ufw status verbose
```
Double-checks the firewall rules — the first command in any "why can't I SSH?" ticket.

```bash
ip addr show | grep -E "inet "
```
Shows the laptop's IP address — the address Kali must connect to (IPs change with DHCP, so always check first).

### Section 2 — Connectivity tests (from the Kali VM)

```bash
nc -zv <server-ip> 22
```
Quick "is the port reachable?" test — faster than nmap, proves network + firewall + service all work.

```bash
nmap -Pn -sV -p 22 --reason <server-ip>
```
Scans only port 22 with version detection; `-Pn` skips host discovery (needed when ping is blocked).

```bash
ssh -v mian@<server-ip>
```
Opens the remote shell with verbose output — the `-v` flag shows the full handshake in real time, matching what Wireshark captures.

### Section 3 — File transfer (SCP & SFTP)

```bash
echo "This is my secret SOC lab file..." > /tmp/soc-secret.txt
```
Creates a test file on Kali to transfer and observe in Wireshark.

```bash
scp /tmp/soc-secret.txt mian@<server-ip>:/tmp/soc-secret-uploaded.txt
```
Securely copies the file to the laptop — encrypted equivalent of FTP `put`. In Wireshark you see a data burst but no plaintext content.

```bash
sftp mian@<server-ip>
```
Opens an interactive SFTP session (like an FTP client, but encrypted).

Inside the SFTP prompt:

```bash
cd "Folder Name with Spaces"
get "filename with spaces.txt"
put /path/to/file
```
Quotes handle spaces in names — without them the commands fail, a common real-world gotcha.

---

## 🛡️ Fail2Ban — SSH Brute-Force Protection

**What is Fail2Ban?** An intrusion-prevention tool that watches log files and automatically bans IPs showing malicious signs (e.g. too many failed logins). Full detail lives in [`fail2ban-commands`](./fail2ban-commands/).

### Install and start (on the Linux laptop)

```bash
sudo apt update
```
Refresh package lists before installing the security tool.

```bash
sudo apt install fail2ban -y
```
Installs Fail2Ban.

```bash
sudo systemctl enable --now fail2ban
```
Starts protection now and on every boot.

```bash
sudo systemctl status fail2ban
```
Confirms it is `Active: active (running)`.

### Check the default SSH jail

```bash
sudo fail2ban-client status sshd
```
Shows failed attempts and currently banned IPs in real time.

### Custom jail configuration (recommended for the lab)

```bash
sudo nano /etc/fail2ban/jail.local
```
Opens the custom config file — defaults are too loose for learning. Paste:

```ini
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
findtime = 10m
bantime = 10m
```

| Setting | Meaning |
|---------|---------|
| `enabled = true` | Activates SSH protection |
| `port = 22` | Protects the SSH port |
| `filter = sshd` | Uses the SSH-specific log filter |
| `logpath = /var/log/auth.log` | Reads failed logins from here |
| `maxretry = 5` | Bans an IP after 5 failed attempts |
| `findtime = 10m` | Counts attempts inside a 10-minute window |
| `bantime = 10m` | Ban lasts 10 minutes |

Save with `Ctrl+O` → Enter → `Ctrl+X`, then:

```bash
sudo systemctl restart fail2ban
```
Applies the new configuration (changes only take effect after restart).

### Simulate the brute-force attack (from the Kali VM)

Manual method (recommended for learning) — type a wrong password 6 times:

```bash
ssh kali@192.168.100.90
```

Fast simulation with a loop:

```bash
for i in {1..8}; do
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 kali@192.168.100.90 "exit" <<< "wrongpassword123"
done
```

### Verify the ban (on the Linux laptop)

```bash
sudo fail2ban-client status sshd
```
Shows the banned IP in the jail status.

```bash
sudo iptables -L -n | grep DROP
```
Confirms the ban at the firewall level — Fail2Ban inserts an iptables DROP rule.

### Unban (when you lock yourself out)

```bash
sudo fail2ban-client set sshd unbanip --all
```
Removes all bans at once.

```bash
sudo fail2ban-client set sshd unbanip YOUR-KALI-IP
```
Unbans one specific IP.

---

## 🔍 Wireshark Analysis

**Display filter:**
```
tcp.port == 22
```

**What to look for:**

1. **Version exchange** — the first plaintext packets (`SSH-2.0-OpenSSH_...`) from client and server.
2. **Key exchange init** — `SSH2_MSG_KEXINIT` packets where both sides negotiate algorithms.
3. **The encryption cliff** — after KEX completes, every subsequent packet is opaque `Encrypted packet` data. You can see *that* data flows (lengths, timing) but never *what* it is.
4. **SCP/SFTP bursts** — during file transfer you see a burst of encrypted packets; compare this with the FTP lab where filenames and contents were readable in plaintext.

> That contrast — readable FTP vs. opaque SSH — is the entire point of the protocol, and seeing it side by side in captures is what makes it stick.

---

## 🚨 SOC Analyst Notes

**How attackers abuse SSH:**

- **Brute force / password spraying** — the #1 SSH attack. Thousands of login attempts against port 22 from botnets. This is exactly what the Fail2Ban half of this lab defends against.
- **Credential stuffing** — leaked username/password pairs replayed against SSH.
- **Stolen private keys** — an unprotected `id_rsa` is a skeleton key; attackers hunt for them in backups, repos, and compromised hosts.
- **SSH as a C2/persistence channel** — reverse SSH tunnels and authorized-key backdoors are classic persistence.

**What to monitor:**

- Failed logon bursts in `/var/log/auth.log` (`Failed password` lines) — the data source Fail2Ban itself uses.
- Logons from unusual source IPs, at unusual hours, or to unusual accounts (especially `root`).
- New entries in `~/.ssh/authorized_keys` — a classic persistence indicator.
- Successful logins immediately after a burst of failures (spray-and-pray that worked).

---

## 🛡️ MITRE ATT&CK

| Technique | ID | Relevance |
|-----------|----|-----------|
| Brute Force | **T1110** | Password guessing against SSH — simulated and blocked in this lab |
| Remote Services: SSH | **T1021.004** | Lateral movement over SSH with valid credentials |
| Valid Accounts | **T1078** | Stolen credentials or keys used for SSH access |
| Denial of Service (defense) | — | Fail2Ban-style rate limiting as a compensating control |

---

## 📸 Screenshots

| Capture | File |
|---------|------|
| SSH handshake & session packets | [`SSH-practice-and-captures/ssh-captures.png`](./SSH-practice-and-captures/ssh-captures.png) |
| SSH capture (continued) | [`SSH-practice-and-captures/ssh-captures2.png`](./SSH-practice-and-captures/ssh-captures2.png) |
| SSH capture (continued) | [`SSH-practice-and-captures/ssh-captures3.png`](./SSH-practice-and-captures/ssh-captures3.png) |

---

## ✅ Key Takeaways

- I set up a working SSH server (OpenSSH + UFW) and connected to it from Kali — `ssh`, `scp`, and `sftp` all ride the same port-22 handshake: version exchange → key exchange → encryption.
- In Wireshark, SSH shows its version string in plaintext and then goes completely opaque — the direct opposite of the FTP lab, and the reason SSH replaced it.
- I deployed Fail2Ban with a custom jail (5 retries / 10-minute window / 10-minute ban), simulated a brute-force attack, watched the IP get banned via `fail2ban-client` and `iptables`, and unbanned it afterwards.
- As a SOC analyst, `/var/log/auth.log` is the ground truth for SSH attacks — failed-password bursts, odd source IPs, and new `authorized_keys` entries are what I now know how to hunt.
