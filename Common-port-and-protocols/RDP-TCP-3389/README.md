


---



```markdown
# RDP (Remote Desktop Protocol - Port 3389) Practical Lab 

By: Muhammad Awais Javed  
Date: May 2026  
## What is RDP?

**Remote Desktop Protocol (RDP)** is a proprietary protocol developed by Microsoft that allows users to connect to another computer over a network and control it as if they were sitting in front of it. It runs on **TCP port 3389** by default.

RDP is widely used in corporate environments for remote work, server management, and technical support. However, it is also one of the **most attacked services** by hackers.

---

## Lab Objective

- Set up Remote Desktop on Windows
- Scan for open RDP port using Nmap
- Capture RDP traffic in Wireshark
- Simulate brute force attack using Hydra from Kali Linux
- Understand how attackers exploit RDP

---

## 1. How to Enable RDP on Windows (Target Machine)

1. Right-click on **This PC** → **Properties**
2. Click **Remote Desktop** on the left
3. Turn on **Remote Desktop**
4. Click **Select users** → Add the user 
5. Allow connections

**Default Port:** 3389

---

## 2. Scanning RDP with Nmap (From Kali)

```bash
# Basic scan
nmap -p 3389 ip

# Version detection
nmap -sV -p 3389 ip

# Aggressive scan
nmap -sS -sV -O -p ip
```

---

## 3. Best Wireshark Filters for RDP

```bash
# Best general filter
rdp || tcp.port == 3389

# New connection attempts
tcp.port == 3389 && tcp.flags.syn == 1

# Failed / Reset connections (Brute force)
tcp.port == 3389 && tcp.flags.rst == 1
```

---

## 4. Brute Force Attack using Hydra (From Kali)

```bash
hydra -l username -P /tmp/mypassword.txt -t 4 -W 2 ip rdp
```

### How Hydra Works:
Hydra is a fast network login cracker. It tries multiple username and password combinations against a service (in this case RDP on port 3389) until it finds the correct one.

**In this lab:**
- We used a small custom wordlist containing possible passwords.


---

## 5. What Happens in Wireshark During Brute Force?

When an attacker uses wrong passwords repeatedly:

- You will see **many TCP SYN** packets (new connection attempts)
- Short-lived connections with **TCP RST** (Reset) packets from the server
- RDP Negotiation packets followed by immediate disconnection
- No full TLS handshake on failed attempts

When the correct password is entered:
- Full RDP handshake completes
- TLS encryption starts
- Application data flows normally

---

**Lab Status:** Completed  
**Tools Used:** Nmap, Wireshark, Hydra, xfreerdp

**SOC Relevance:**  
RDP is one of the top attack vectors used by ransomware groups and hackers. Understanding how brute force attacks look in Wireshark and Nmap is essential for SOC Analysts.

---

