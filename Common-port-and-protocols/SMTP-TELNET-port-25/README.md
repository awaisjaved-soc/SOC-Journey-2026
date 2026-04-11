
```markdown
# Port 25 SMTP Lab - Raw Telnet Email Sending

**SOC Journey 2026**  
**Student:** Muhammad Awais Javed (Mian Awais)  
**Date:** April 12, 2026

---

## 🎯 Objective

To understand how SMTP (Simple Mail Transfer Protocol) works by manually sending emails using **raw Telnet** on Port 25. This lab simulates real-world email server behavior that SOC Analysts monitor daily.

---

## 📋 Lab Overview

- Installed and configured **Postfix** (SMTP Server) on Kali Linux
- Sent emails using **raw Telnet** (no email client)
- Successfully sent and received emails between Kali VM and Linux Laptop
- Understood SMTP commands (`EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`)

---

## 🔧 Step-by-Step Lab

### 1. Install Postfix

```bash
sudo apt update
sudo apt install postfix -y
```
*(During installation, choose **"Internet Site"**)

### 2. Configure Postfix (Working Configuration)

```bash
# Stop Postfix
sudo systemctl stop postfix

# Backup original config
sudo cp /etc/postfix/main.cf /etc/postfix/main.cf.bak_$(date +%F)

# Create clean working configuration
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

# Fix master.cf (remove chroot issues)
sudo sed -i 's/^smtp[[:space:]]\+inet[[:space:]]\+n[[:space:]]\+-.*$/smtp inet n - y - - smtpd/' /etc/postfix/master.cf

# Restart and verify
sudo systemctl restart postfix
sudo systemctl status postfix
sudo postfix check
```

**Why these settings?**
- `inet_interfaces = all` → Allows connections from other devices (not just localhost)
- `mynetworks` → Defines which IPs are trusted
- `smtpd_banner` → Custom banner shown when someone connects (visible in SOC monitoring)
- `home_mailbox = Maildir/` → Saves emails in `~/Maildir` folder

---

### 3. Test SMTP Server

```bash
# Local test
telnet 127.0.0.1 25

# From another device (Linux Laptop)
telnet 192.168.100.90 25     # ← Use your Kali IP
```

---

### 4. Send Email using Raw Telnet (Working Commands)

After connecting and seeing `220` banner, type:

```bash
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

**Important Notes:**
- Always use full email format (`user@domain`)
- End email with single dot `.` on new line
- `RCPT TO` must be a valid local user (`kali` in this setup)

---

### 5. Check Received Emails

```bash
ls ~/Maildir/new/
cat ~/Maildir/new/*
```

---

## 🛠️ SOC Analyst Context (Why This Lab Matters)

- Port 25 is commonly used by spammers and phishing attackers.
- SOC Analysts monitor port 25 for:
  - Open mail relays
  - Brute force attempts
  - Unusual `MAIL FROM` / `RCPT TO` patterns
  - Spam campaigns
- Understanding raw SMTP helps in log analysis and incident response.

---
