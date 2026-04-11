


---

```markdown
# Telnet + SMTP Port 25 Practical Lab

**Author:** Muhammad Awais Javed (Mian Awais)  
**Date:** April 2026  
**Part of:** SOC-Journey-2026

### Objective
To understand how SMTP works on Port 25 using Telnet, capture the entire session in Wireshark, and see why it is insecure (everything in plaintext).

### What is SMTP Port 25?
- SMTP = Simple Mail Transfer Protocol
- Used for sending emails between servers
- Port 25 is the default port for SMTP
- It uses **TCP** (not UDP) because email delivery must be reliable

### Why We Use Telnet for this Lab?
Telnet allows us to manually type SMTP commands and see the full conversation in plaintext. This is the best way to understand the protocol.

---

### Full Practical Setup (A to Z)

#### 1. On Server Side (Linux Laptop - IP: 192.168.100.90)

```bash
sudo apt update
```
**What it does:** Updates package list  
**Why:** To get latest packages

```bash
sudo apt install postfix -y
```
**What it does:** Installs Postfix SMTP server  
**Why:** Postfix will act as our email server

During installation choose:
- **Internet Site**
- System mail name: `kali.local` (or press Enter)

```bash
sudo systemctl restart postfix
sudo systemctl status postfix
```
**What it does:** Restarts and checks if Postfix is running  
**Why:** To make sure the server is active

```bash
sudo ss -tlnp | grep :25
```
**What it does:** Shows if port 25 is listening  
**Why:** To confirm SMTP server is ready

```bash
sudo ufw allow 25/tcp
sudo ufw reload
```
**What it does:** Allows port 25 through firewall  
**Why:** Without this, other devices cannot connect

---

#### 2. On Client Side (Kali VM) - Start Capture

- Open Wireshark
- Select interface `eth0`
- Apply filter: `tcp.port == 25`
- Start capturing

---

#### 3. Connect using Telnet & Send Email Manually (From Kali)

```bash
telnet 192.168.100.90 25
```

Once connected, type the following commands **one by one** (press Enter after each):

```
EHLO test
MAIL FROM:<test@kali>
RCPT TO:<kali>
DATA

Subject: Telnet SMTP Lab Test - Mian Awais

This is the email body sent manually using Telnet.
 Port 25 Practical
Everything is in plaintext here.
.
QUIT
```

**Important:**
- After `DATA`, press Enter **twice** (leave one blank line)
- End the email with a single `.` on its own line

---

### What You Should See in Wireshark

- TCP 3-way handshake on port 25
- Plaintext SMTP commands:
  - `EHLO test`
  - `MAIL FROM:<test@kali>`
  - `RCPT TO:<kali>`
  - `DATA`
  - Email subject and body
  - `QUIT`

This is the main learning point: **SMTP on port 25 sends everything in plaintext** (unlike SSH).

---

### Check Received Email on Server (Laptop)

```bash
cat /var/mail/kali
```

or

```bash
sudo tail -n 50 /var/mail/kali
```

---



