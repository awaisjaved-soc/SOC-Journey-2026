# 🖥️ RDP — Port 3389 | Practical Lab

**Author:** Muhammad Awais Javed (Mian Awais)
**Date:** May 2026
**Part of:** [SOC-Journey-2026](https://github.com/awaisjaved-soc/SOC-Journey-2026)

---
## 📌 Table of Contents
- [🎯 Objective](#-objective)
- [📖 What is RDP?](#-what-is-rdp)
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

- Enable Remote Desktop on a Windows target machine
- Scan for the open RDP port with Nmap
- Capture RDP traffic in Wireshark
- Simulate a **brute-force attack with Hydra** from Kali Linux
- Learn what an RDP attack looks like on the wire — failed logins vs a successful session

---
## 📖 What is RDP?

**RDP (Remote Desktop Protocol)** is Microsoft's proprietary protocol for connecting to another computer over a network and controlling it as if you were sitting in front of it. It runs on **TCP port 3389** by default.

### Where it's used

| Use case | Example |
|----------|---------|
| Remote work | Employees connecting to office PCs |
| Server management | Admins managing Windows servers |
| Technical support | Helpdesk taking over a user's screen |

### Why SOC analysts care

RDP is one of the **most attacked services on the internet** — a favorite initial-access vector for ransomware groups. Exposed RDP + weak credentials = one of the most common breach stories in existence.

---
## ⚙️ How It Works

```
[ Attacker / Client ]                    [ Windows Target :3389 ]
        |                                              |
        |--- 1. TCP handshake (SYN/SYN-ACK/ACK) ------>|
        |--- 2. RDP Negotiation Request ------------->|
        |<-- 3. Negotiation Response (TLS chosen) ----|
        |--- 4. TLS handshake (encryption starts) -->|
        |--- 5. Login with username + password ----->|
        |<-- 6. Session established (desktop stream)-|
```

- A **failed login** dies early: negotiation starts, credentials are rejected, and the server tears the connection down (you'll see TCP RST).
- A **successful login** completes the TLS handshake and the encrypted desktop session begins.

---
## 🧪 Lab Environment

| Role | Machine | Details |
|------|---------|---------|
| Target | Windows (RDP enabled) | RDP on TCP 3389 |
| Attacker | Kali Linux | Nmap, Hydra, Wireshark, `xfreerdp` |

---
## 💻 Commands Used

### 1. Enable RDP on the Windows target

1. Right-click **This PC** → **Properties**
2. Click **Remote Desktop** on the left
3. Turn **on** Remote Desktop
4. Click **Select users** → add the allowed user
5. Allow the connections

**Default port:** `3389`

### 2. Scan RDP with Nmap (from Kali)

```bash
# Basic port check — is 3389 open?
nmap -p 3389 <target-ip>

# Version detection — what RDP service is running?
nmap -sV -p 3389 <target-ip>

# Aggressive scan — SYN scan + version + OS detection on RDP
nmap -sS -sV -O -p 3389 <target-ip>
```

### 3. Brute-force RDP with Hydra (from Kali)

```bash
# Hydra against RDP with a custom wordlist (-t 4 = 4 parallel tasks, -W 2 = wait 2s)
hydra -l username -P /tmp/mypassword.txt -t 4 -W 2 <target-ip> rdp

# Hydra against a real target with rockyou.txt
hydra -l Admin -P /usr/share/wordlists/rockyou.txt 192.168.100.27 rdp
```

**How Hydra works:** it is a fast network login cracker — it tries username/password combinations against the service (here RDP on 3389) until one succeeds. In this lab I used a small custom wordlist of likely passwords.

```bash
# Connect with a successful credential using FreeRDP
xfreerdp /u:Admin /p:<found-password> /v:192.168.100.27
```

---
## 🔍 Wireshark Analysis

Capture on the Kali interface during the attack, then use these display filters:

```
rdp || tcp.port == 3389
```
> Best general filter — all RDP traffic.

```
tcp.port == 3389 && tcp.flags.syn == 1
```
> New connection attempts — spikes here mean someone is knocking.

```
tcp.port == 3389 && tcp.flags.rst == 1
```
> Failed/reset connections — the signature of brute force.

### What a brute-force attack looks like

When the attacker keeps guessing wrong passwords:
- **Many TCP SYN packets** — rapid new connection attempts
- Short-lived connections ending in **TCP RST** (Reset) from the server
- RDP **Negotiation** packets followed by immediate disconnection
- **No full TLS handshake** on the failed attempts

### What a successful login looks like
- Full RDP handshake completes
- **TLS encryption starts**
- Application data (the desktop session) flows normally

### On disconnect
After the RDP session is closed, the final packets are teardown — in my capture the last red-highlighted line was the final packet right after the last ACK.

---
## 🚨 SOC Analyst Notes

**How attackers abuse RDP:**
- **Brute force / password spraying** against port 3389 — especially effective where there is no lockout policy
- **Exposed RDP on the internet** — attackers scan the whole IPv4 space (and Shodan) for `port:3389` and hammer whatever answers
- Stolen credentials reused on RDP give an instant interactive foothold — ransomware groups love this

**What to monitor / alert on:**
- Burst of **SYN → RST** cycles on 3389 from a single source (brute force)
- RDP logins at unusual hours or from unusual geolocations
- First-time RDP logins for a user, or logins from a new source IP
- Windows Event IDs **4624** (logon type 10 = RDP) and **4625** (failed logon) on the target host
- Any RDP exposed directly to the internet — it should sit behind a VPN

---
## 🛡️ MITRE ATT&CK

| Technique | ID | Relevance |
|-----------|----|-----------|
| Remote Services: Remote Desktop Protocol | T1021.001 | Abusing RDP for remote access |
| Brute Force | T1110 | Hydra password guessing on 3389 |
| Valid Accounts | T1078 | Logging in with stolen/cracked credentials |

---
## 📸 Screenshots

> No static capture files were saved for this lab — the packet behavior described above (SYN/RST storms on failed logins, full TLS handshake on success, teardown packets on disconnect) is what I observed live in Wireshark during the Hydra brute-force run.

---
## ✅ Key Takeaways

- RDP (TCP 3389) gives full interactive control of a Windows machine — which is exactly why attackers want it.
- A brute-force attack is unmistakable on the wire: **SYN floods and RST packets**, negotiations that die before TLS.
- A successful login looks completely different: clean handshake, TLS, steady session traffic.
- Nmap finds it, Hydra breaks weak credentials, Wireshark proves what happened — the full attack/defense loop in one lab.
- **Lab status:** completed. **Tools used:** Nmap, Wireshark, Hydra, xfreerdp.
