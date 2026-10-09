# 📧 SMTP — Port 25 | Practical Lab (Raw Telnet Email)

**Author:** Muhammad Awais Javed (Mian Awais)
**Date:** April 12, 2026
**Part of:** [SOC-Journey-2026](https://github.com/awaisjaved-soc/SOC-Journey-2026)

---
## 📌 Table of Contents
- [🎯 Objective](#-objective)
- [📖 What is SMTP?](#-what-is-smtp)
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

- Understand how **SMTP (Simple Mail Transfer Protocol)** works by sending email **manually with raw Telnet** on port 25 — no email client
- Install and configure **Postfix** as a working mail server on Kali Linux
- Send and receive emails between my Kali VM and my Linux laptop
- Learn the raw SMTP commands (`EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`) that SOC analysts see in mail logs every day

---
## 📖 What is SMTP?

**SMTP (Simple Mail Transfer Protocol)** is the protocol that **sends** email across the internet. It runs on **TCP port 25** (with 587/465 used for encrypted submission).

### The email protocol family

| Protocol | Port | Job |
|----------|------|-----|
| **SMTP** | 25 (587/465 for submission) | **Sending** mail |
| POP3 | 110 / 995 | **Receiving** mail (download to one device) |
| IMAP | 143 / 993 | **Receiving** mail (synced across devices) |

### Real-life example

When you hit "send" in Gmail, your client speaks SMTP to Google's server, which speaks SMTP to the recipient's server, which finally drops it in their inbox. Every hop is logged — and SOC analysts read those logs hunting phishing and spam.

---
## ⚙️ How It Works

A raw SMTP conversation (exactly what I typed in this lab):

```
[ Client (Telnet) ]                    [ Postfix Server :25 ]
        |                                            |
        |<-- 220 kali.local ESMTP Postfix ----------|  (greeting banner)
        |--- EHLO test --------------------------->|
        |<-- 250 OK --------------------------------|
        |--- MAIL FROM:<mianawais@kali.local> ---->|
        |<-- 250 OK --------------------------------|
        |--- RCPT TO:<kali@kali.local> ----------->|
        |<-- 250 OK --------------------------------|
        |--- DATA -------------------------------->|
        |<-- 354 End with . ------------------------|
        |--- Subject: ... + body + \r\n.\r\n ----->|
        |<-- 250 OK: queued ------------------------|
        |--- QUIT -------------------------------->|
```

Every line is a command, every reply is a 3-digit code (`220` = ready, `250` = OK, `354` = send the message now). The email ends with a single `.` on its own line.

---
## 🧪 Lab Environment

| Role | Machine | Details |
|------|---------|---------|
| SMTP server (Postfix) | Kali Linux | `myhostname = kali.local` |
| Sender | Kali VM | Raw Telnet on port 25 |
| Receiver | Linux laptop | Local user `kali` |

---
## 💻 Commands Used

### 1. Install Postfix

```bash
# Update packages and install the Postfix mail server
sudo apt update
sudo apt install postfix -y
```
> During installation, choose **"Internet Site"** when asked for the mail configuration type.

### 2. Configure Postfix (working configuration)

```bash
# Stop Postfix before editing the config
sudo systemctl stop postfix

# Back up the original config (timestamped, so I never lose it)
sudo cp /etc/postfix/main.cf /etc/postfix/main.cf.bak_$(date +%F)

# Write a clean, minimal working configuration
sudo bash -c 'cat > /etc/postfix/main.cf' << 'EOF'
myhostname = kali.local
mydomain = local
inet_interfaces = all
inet_protocols = all
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8
mydestination = $myhostname, localhost.localdomain, localhost
home_mailbox = Maildir/
smtpd_banner = $myhostname ESMTP Postfix (SOC Lab - Mian Awais)
compatibility_level = 3.6
EOF
```

**Why these settings matter:**

| Setting | What it does |
|---------|--------------|
| `inet_interfaces = all` | Accept connections from other devices, not just localhost |
| `mynetworks` | Defines which IP ranges are trusted to relay mail |
| `smtpd_banner` | Custom greeting banner — visible to anyone connecting (and to SOC monitoring) |
| `home_mailbox = Maildir/` | Deliver received mail into `~/Maildir/` folders |
| `mydestination` | Which domains this server accepts mail for |

```bash
# Fix master.cf — remove chroot-related startup issues on the smtp line
sudo sed -i 's/^smtp[[:space:]]\+inet[[:space:]]\+n[[:space:]]\+-.*$/smtp inet n - y - - smtpd/' /etc/postfix/master.cf

# Restart Postfix, verify it is running, and check the config for errors
sudo systemctl restart postfix
sudo systemctl status postfix
sudo postfix check
```

### 3. Test the SMTP server

```bash
# Connect from the local machine
telnet 127.0.0.1 25

# Connect from another device on the LAN (use your Kali IP — mine was 192.168.100.90)
telnet 192.168.100.90 25
```
> You should see the `220 kali.local ESMTP Postfix (SOC Lab - Mian Awais)` banner.

### 4. Send an email using raw Telnet

After connecting and seeing the `220` banner, type these commands exactly:

```
EHLO test
MAIL FROM:<mianawais@kali.local>
RCPT TO:<kali@kali.local>
DATA
Subject: Test Email from SOC Lab

Hello, this is a manual email sent using Telnet on Port 25.
Mian Awais SOC Journey 2026.
.
QUIT
```

**Important notes:**
- Always use the full email format (`user@domain`)
- The message **ends with a single dot `.` on its own line**
- `RCPT TO` must be a valid local user (`kali` in this setup)

### 5. Check the received email

```bash
# List newly arrived mail
ls ~/Maildir/new/

# Read the raw message (headers + body, exactly as SMTP delivered it)
cat ~/Maildir/new/*
```

---
## 🔍 Wireshark Analysis

Capture on the sender's interface while running the Telnet session:

```
tcp.port == 25
```
> All SMTP traffic.

```
smtp
```
> SMTP protocol packets, decoded.

### What to look for

| What you see | What it means |
|--------------|---------------|
| `220` banner | Server greeting — note the **custom banner text** (fingerprinting info) |
| `EHLO` / `HELO` | Client introducing itself |
| `MAIL FROM:` | The **claimed sender** — trivially forgeable, which is why phishing works |
| `RCPT TO:` | The recipient |
| `DATA` + message body | The email content in **cleartext** on port 25 |
| `.` then `250 OK` | Message accepted for delivery |

> 🔑 Key observation: on port 25 everything — sender address, recipient, subject, body — crosses the wire readable. Anyone can claim to be anyone in `MAIL FROM:`, which is the root of email spoofing.

---
## 🚨 SOC Analyst Notes

**How attackers abuse SMTP / port 25:**
- **Phishing & spoofing** — `MAIL FROM` is unauthenticated on basic SMTP, so attackers forge trusted senders
- **Spam campaigns** — compromised hosts blasting thousands of messages through port 25
- **Open relays** — misconfigured servers that forward anyone's mail, abused by spammers
- **Brute force** — credential guessing against SMTP AUTH where it is enabled

**What to monitor / alert on:**
- Unexpected **outbound port 25** from workstations (a laptop should never be a mail server — this screams compromised host / botnet)
- Unusual `MAIL FROM` / `RCPT TO` patterns and sudden volume spikes
- Connections to **open mail relays**
- Banner anomalies — a non-standard `220` banner can identify rogue mail servers on the network

---
## 🛡️ MITRE ATT&CK

| Technique | ID | Relevance |
|-----------|----|-----------|
| Phishing | T1566 | Forged `MAIL FROM` / malicious emails sent over SMTP |
| Brute Force | T1110 | Password guessing against SMTP AUTH |
| Valid Accounts | T1078 | Using compromised mailbox credentials to send mail |

---
## 📸 Screenshots

| Screenshot | Description |
|------------|-------------|
| ![Telnet session 1](telnet%201.png) | Raw Telnet session to port 25 — banner, `EHLO`, and mail commands |
| ![Telnet session 2](telnet%202.png) | Completing the SMTP conversation and sending the message |

---
## ✅ Key Takeaways

- SMTP (TCP 25) is a **text conversation**: `EHLO` → `MAIL FROM` → `RCPT TO` → `DATA` → `.` → `QUIT` — and I typed every line by hand.
- I built a working Postfix server, configured it from a blank `main.cf`, and delivered real mail between two machines.
- On port 25, **everything is cleartext and the sender address is forgeable** — the two facts behind phishing and why SOC teams watch this port.
- A workstation suddenly talking outbound port 25 is one of the simplest, strongest compromise indicators there is.
