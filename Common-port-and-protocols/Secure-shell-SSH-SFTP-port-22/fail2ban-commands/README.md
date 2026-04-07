
**Bro, I got you 100%** — your SOC-Journey-2026 GitHub repo and LinkedIn profile are **your data**, your hard work, your project. I’m not touching, deleting, or messing with any history, files, or anything else. Respect.

Here is the **complete ready-made A to Z Fail2Ban lab** written exactly like you wanted — clean, professional, with every command + **What it does** + **Why we use it** + **SOC context**.  

You can **copy-paste the entire thing** directly into your GitHub repo as `README.md` (or as a separate file called `Fail2Ban-Lab.md`).

---

```markdown
# Fail2Ban Lab - SSH Brute Force Protection (Port 22)

**Author:** Muhammad Awais Javed (Mian Awais)  
**Date:** April 2026  
**Part of:** SOC-Journey-2026

### What is Fail2Ban?
Fail2Ban is an intrusion prevention tool that monitors log files and automatically bans IP addresses that show malicious signs (e.g., too many failed login attempts).

### Lab Objective
- Install and configure Fail2Ban on Linux server
- Protect SSH port 22 from brute-force attacks
- Simulate real attacker behavior
- Understand how SOC analysts use it in production

### Why This Lab Matters for Junior SOC Analyst
In real Pakistani SOCs (banks, telcos, government), Fail2Ban is one of the first tools deployed on Linux servers to stop brute-force attacks on SSH.

---

### Step-by-Step Practical Commands

#### 1. Install Fail2Ban on Linux Laptop (SSH Server)

```bash
sudo apt update
```
**What it does:** Updates the package list.  
**Why we use it:** Ensures we install the latest version of Fail2Ban.  
**SOC context:** Always update before installing security tools.

```bash
sudo apt install fail2ban -y
```
**What it does:** Installs the Fail2Ban package.  
**Why we use it:** This is the actual tool that will monitor logs and ban IPs.

```bash
sudo systemctl enable --now fail2ban
```
**What it does:** Enables and starts the Fail2Ban service immediately.  
**Why we use it:** So protection runs automatically on every boot.

```bash
sudo systemctl status fail2ban
```
**What it does:** Shows current status of the service.  
**Why we use it:** To confirm it is "Active: active (running)".

#### 2. Check Default SSH Jail

```bash
sudo fail2ban-client status sshd
```
**What it does:** Shows status of the SSH protection jail.  
**Why we use it:** To see failed attempts and banned IPs in real time.

#### 3. Create Custom Configuration (Recommended for Lab)

```bash
sudo nano /etc/fail2ban/jail.local
```
**What it does:** Creates/Opens the custom configuration file.  
**Why we use it:** Default settings are too loose for learning.

**Paste the following inside the file:**

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

**Explanation of each line:**
- `enabled = true` → Activates protection for SSH
- `port = 22` → Protects SSH port
- `filter = sshd` → Uses SSH-specific log filter
- `logpath = /var/log/auth.log` → Reads failed login logs from here
- `maxretry = 5` → Bans IP after 5 failed attempts
- `findtime = 10m` → Counts attempts within 10 minutes
- `bantime = 10m` → Bans IP for 10 minutes

Save file: `Ctrl+O` → Enter → `Ctrl+X`

```bash
sudo systemctl restart fail2ban
```
**What it does:** Restarts Fail2Ban to apply new config.  
**Why we use it:** Changes take effect only after restart.

#### 4. Simulate Brute Force Attack (From Kali VM)

**Manual method (recommended for learning):**
```bash
ssh kali@192.168.100.90
```
→ Type **wrong password** 6 times manually.

**Or using loop (fast simulation):**
```bash
for i in {1..8}; do 
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 kali@192.168.100.90 "exit" <<< "wrongpassword123"
done
```

#### 5. Verify Ban (On Linux Laptop)

```bash
sudo fail2ban-client status sshd
```

```bash
sudo iptables -L -n | grep DROP
```

#### 6. Unban IP (When You Get Banned)

```bash
# Unban all IPs
sudo fail2ban-client set sshd unbanip --all

# Or unban specific IP
sudo fail2ban-client set sshd unbanip YOUR-KALI-IP
```

---

### Real SOC Context (What to write on GitHub/LinkedIn)

- Installed and configured Fail2Ban to protect SSH port 22.
- Set custom policy: ban after 5 failed attempts for 10 minutes.
- Successfully simulated brute-force attack and observed automatic IP banning.
- Learned how to monitor logs (`/var/log/auth.log`) and manage bans using `fail2ban-client`.

**Tools used:** Fail2Ban, iptables, SSH, auth.log

This lab demonstrates real-world defensive security skills required for Junior SOC Analyst roles in Pakistan.

---

