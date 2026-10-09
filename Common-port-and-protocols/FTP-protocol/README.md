# 📁 FTP — Port 21 | Practical Lab

**Author:** Muhammad Awais Javed (Mian Awais) · **Date:** April 2026 · **Part of:** [SOC-Journey-2026](https://github.com/awaisjaved-soc/SOC-Journey-2026)

---

## 📌 Table of Contents

- [🎯 Objective](#-objective)
- [📖 What is FTP?](#-what-is-ftp)
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

To set up a real FTP server, log in anonymously, transfer a file, and capture the whole conversation in Wireshark — so I can see with my own eyes why FTP is considered dangerous and what its traffic looks like to a SOC analyst.

---

## 📖 What is FTP?

**FTP = File Transfer Protocol.** Its only job is: send and receive files between two computers over the network. It runs on **port 21** (control channel).

### Where You Still See FTP in Real Life

- **Old websites:** many small companies and legacy hosting setups still use FTP to upload website files (`index.html`, images) from a laptop to the web server.
- **Internal company file sharing:** banks, factories, government offices, and small businesses move big files (reports, invoices, software updates) between departments over FTP.
- **Software vendors:** some older vendors still distribute updates via FTP.
- **Backup systems:** some automatic backup tools upload files to a server using FTP.

### The Big Problem

FTP is from **1985** — very old. It was designed before security was a big concern, so **everything travels in plain text**: username, password, and file contents. That's why it's dangerous in 2026, and why SOC analysts treat FTP traffic as inherently suspicious.

---

## ⚙️ How It Works

FTP is unusual because it uses **two separate connections**:

```
Client                                              FTP Server (port 21)
  |                                                        |
  | --- TCP 21: USER anonymous --------------------------> |
  | <---------- 331 Please specify the password --------- |
  | --- TCP 21: PASS (blank) ---------------------------> |
  | <---------- 230 Login successful ------------------- |
  | --- TCP 21: PASV (request data channel) ------------> |
  | <---------- 227 Entering Passive Mode (port X) ------ |
  | --- TCP port X: RETR test.txt (file download) ------> |
  | <---------- [file contents in PLAINTEXT] ------------ |
```

- **Port 21 — control channel:** carries commands (`USER`, `PASS`, `LIST`, `GET`) and server replies. Always on port 21.
- **Data channel — dynamic port:** carries the actual file transfer (in active or passive mode). This is why FTP can be annoying for firewalls — the data port changes.
- **Anonymous login:** many servers allow logging in with username `anonymous` and any/blank password — convenient for public file archives, risky everywhere else.

---

## 🧪 Lab Environment

| Machine | Role | IP |
|---|---|---|
| Kali Linux | FTP server (vsftpd) + client + Wireshark | `127.0.0.1` (localhost) |

**Tools:** Kali Linux · `vsftpd` (Very Secure FTP Daemon) · Nmap · Wireshark

---

## 💻 Commands Used

Every command I ran, with what each one does:

```bash
sudo apt update
```
Updates the package list so `apt` knows the latest available software versions.

```bash
sudo apt install vsftpd -y
```
Installs the FTP server software — `vsftpd` (Very Secure FTP Daemon, ironically not very secure in its default/plaintext nature).

```bash
sudo nano /etc/vsftpd.conf
```
Opens the main vsftpd settings file so I can change the server's rules. I changed:

```conf
anonymous_enable=YES
```
Allows anyone to log in **without a real password** (anonymous login). For this lab demo only — never do this on a real server.

```bash
sudo systemctl restart vsftpd
```
Restarts the FTP server so the configuration change takes effect.

```bash
echo "This is my secret file..." | sudo tee /srv/ftp/test.txt
```
Creates a test file inside the FTP shared folder (`/srv/ftp/`) so I have something to download. `tee` writes the text to the file (with `sudo` for permission).

**Connecting as a client:**

```bash
ftp 127.0.0.1
```
Starts the FTP client and connects to my own machine (`127.0.0.1` = localhost).

```
Name: anonymous
Password: (blank)
```
Logs in without real credentials — this works because I enabled `anonymous_enable=YES`.

```ftp
ls
```
Lists files on the FTP server (like the `dir` command) — confirms `test.txt` is there.

```ftp
get test.txt
```
Downloads `test.txt` from the server to my current local folder.

```ftp
bye
```
Closes the FTP connection.

**Recon with Nmap:**

```bash
nmap -p 21 127.0.0.1
```
Scans port 21 to confirm the FTP service is open and reachable.

```bash
nmap -sV -p 21 127.0.0.1
```
`-sV` probes the open port to identify the **service version** (e.g., vsftpd 3.x) — version info helps an analyst know what's running.

```bash
nmap --script ftp-anon -p 21 127.0.0.1
```
Runs Nmap's `ftp-anon` script, which specifically tests whether **anonymous login is allowed** — exactly the misconfiguration I set up. Attackers run this to find easy targets.

**Capture in Wireshark:**
- Display filter: `ftp`
- Right-click a packet → **Follow → TCP Stream**

This reconstructs the entire conversation — and you can read every word: the username, the (blank) password, the `LIST` output, and the file contents — all in plain text.

---

## 🔍 Wireshark Analysis

**Useful display filters:**

| Filter | What it shows |
|---|---|
| `ftp` | All FTP control-channel traffic |
| `ftp.request.command == "USER"` | Login attempts (usernames visible) |
| `ftp.request.command == "PASS"` | Password submissions (visible in plaintext!) |
| `ftp.response.code == 230` | Successful logins |
| `ftp.response.code == 530` | Failed logins |

**What to look for in the capture:**
- `USER anonymous` followed by `PASS` with an empty/blank password — the anonymous login, readable by anyone watching.
- `230 Login successful` — the server accepting it.
- The **Follow TCP Stream** view shows the complete session like a chat transcript: commands, directory listing, and the downloaded file's contents — **zero encryption**.
- If this were a real user instead of anonymous, their actual password would be sitting in the capture in clear text.

---

## 🚨 SOC Analyst Notes

**How attackers abuse FTP:**
- **Credential theft** — sniffing FTP logins off the network (coffee-shop Wi-Fi, compromised switches, MITM) gives immediate server access.
- **Anonymous access abuse** — misconfigured servers with `anonymous_enable=YES` (exactly what I set up) get found by scanners and used for hosting malware or stolen data.
- **Data exfiltration** — FTP is a classic exfil channel: simple, rarely blocked outbound on legacy networks.
- **Brute-forcing** — weak FTP passwords are hammered by automated tools; port 21 is one of the most scanned ports on the internet.

**What to monitor / alert on:**
- Any **plaintext credential** use — push for SFTP/FTPS migration wherever FTP is found.
- **Anonymous logins** (`USER anonymous` + `230` success) — almost never legitimate on internal servers.
- **Multiple `530` failures** from one source → possible brute-force against port 21.
- **Large or unusual file transfers** at odd hours → possible exfiltration.
- FTP traffic to **external IPs** from servers that shouldn't be talking to the internet.

---

## 🛡️ MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| Exfiltration Over Alternative Protocol | [T1048](https://attack.mitre.org/techniques/T1048/) | Stealing data out over FTP |
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | Abusing anonymous/default FTP credentials |
| Network Sniffing | [T1040](https://attack.mitre.org/techniques/T1040/) | Harvesting FTP credentials from plaintext traffic |
| Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | Password-guessing against FTP logins |

---

## 📸 Screenshots

No screenshots were saved for this lab — the analysis was done live in Wireshark using **Follow → TCP Stream** on the `ftp` filter. The key evidence (plaintext `USER`/`PASS`, directory listing, file contents) is described in the [Wireshark Analysis](#-wireshark-analysis) section above.

---

## ✅ Key Takeaways

- FTP (1985) sends **everything in plaintext** — usernames, passwords, and file contents.
- I set up `vsftpd` with anonymous login enabled, transferred a file, and read the entire session — credentials included — in Wireshark's Follow TCP Stream.
- Nmap's `ftp-anon` script finds exactly this misconfiguration in seconds — attackers scan for it constantly.
- As an analyst: treat FTP as legacy and suspicious, alert on anonymous logins and brute-force patterns, and push for SFTP/FTPS everywhere.
