


```markdown
# SSH Port 22 Full Commands Sheet 

## Section 1: SSH Server Setup on Linux Laptop (the server)

sudo apt update && sudo apt install openssh-server -y
```
**What it does:** Updates package list and installs the OpenSSH server package.  
**Why we use it:** To make sure the SSH service is installed and ready to listen on port 22.  
**Explanation:** This is the first step to turn your Linux laptop into an SSH server. Without it, no one can connect remotely.

### Command
```bash
sudo systemctl enable --now ssh
```
**What it does:** Enables the SSH service and starts it immediately.  
**Why we use it:** So the service runs now and automatically on every reboot.  
**Explanation:** In real SOC jobs you will check this on production servers — if it’s not enabled, remote management fails.

### Command
```bash
sudo systemctl status ssh
```
**What it does:** Shows if the SSH service is running, its process ID, and recent logs.  
**Why we use it:** To verify the server is healthy before testing from Kali.  
**Explanation:** You saw “Active: active (running)” — this is your daily SOC check.

### Command
```bash
sudo ss -tlnp | grep :22
```
**What it does:** Lists all listening TCP ports and shows which process is using them.  
**Why we use it:** To confirm SSH is really listening on port 22 on all interfaces (0.0.0.0:22).  
**Explanation:** This is the command SOC analysts use to prove a service is open and ready.

### Command
```bash
sudo ufw allow ssh
```
**What it does:** Adds a firewall rule to allow incoming connections on port 22.  
**Why we use it:** UFW was blocking traffic; this opens the door safely.  
**Explanation:** Real servers have firewalls — you will add this rule in every Linux server audit.

### Command
```bash
sudo ufw enable
```
**What it does:** Turns the UFW firewall on.  
**Why we use it:** It was inactive; enabling it applies all rules.  
**Explanation:** You saw “Status: active” after this — now your laptop is protected like a real production server.

### Command
```bash
sudo ufw status verbose
```
**What it does:** Shows firewall status and all active rules.  
**Why we use it:** To double-check that port 22 is ALLOW IN.  
**Explanation:** SOC ticket: “Why can’t I SSH?” → first command you run.

### Command
```bash
ip addr show | grep -E "inet "
```
**What it does:** Shows all IP addresses on the machine.  
**Why we use it:** To confirm the exact **ip** that Kali must connect to.  
**Explanation:** IPs can change with DHCP — always check this first.

---

## Section 2: Connectivity Tests from Kali VM (the client)

### Command
```bash
nc -zv ip 22
```
**What it does:** Tests if TCP port 22 is open (no data sent).  
**Why we use it:** Faster than nmap for quick “is the port reachable?” check.  
**Explanation:** You saw “open” — this proves network + firewall + SSH service all work.

### Command
```bash
nmap -Pn -sV -p 22 --reason ip
```
**What it does:** Scans only port 22, skips host discovery, shows version and reason.  
**Why we use it:** Normal nmap fails because ping is blocked; -Pn fixes it.  
**Explanation:** This is the exact command you will run daily as Junior SOC Analyst when investigating open ports.

### Command
```bash
ssh -v @mian@ip
```
**What it does:** Starts a secure remote shell with verbose output.  
**Why we use it:** This is the remote connection (replaces FTP).  
**Explanation:** The -v shows you the full handshake in real time (exactly what you see in Wireshark).

---

## Section 3: File Transfer Commands (SCP & SFTP)

### Command
```bash
echo "This is my secret SOC lab file..." > /tmp/soc-secret.txt
```
**What it does:** Creates a test file on Kali.  
**Why we use it:** So we have something to transfer and watch in Wireshark.  
**Explanation:** Same as the file we created in FTP lab.

### Command
```bash
scp /tmp/soc-secret.txt @mian@ip:/tmp/soc-secret-uploaded.txt
```
**What it does:** Securely copies the file from Kali to Linux laptop.  
**Why we use it:** SCP = Secure Copy over SSH (encrypted version of FTP put).  
**Explanation:** You see the data burst in Wireshark but no plaintext content.

### Command
```bash
sftp @mian@ip
```
**What it does:** Opens an interactive SFTP session (like FTP client).  
**Why we use it:** Lets you run ls, cd, get, put inside one session.  
**Explanation:** This is what you were doing when you saw the files (Desktop, Documents, etc.).

#### Inside SFTP prompt:
```bash
cd "Folder Name with Spaces"
get "filename with spaces.txt"
put /path/to/file
```
**Explanation:** Quotes handle spaces in names. Without them, commands fail — common real-world gotcha.

---

## Section 4: How the Two Devices Actually Connect (SSH vs FTP)

- **FTP way:**  
  ```bash
  ftp ip
  ```
  → then login. Uses port 21 (control) + 20 (data). Everything plaintext.

- **SSH way:**  
  ```bash
  ssh @mian@ip
  sftp @mian@ip
  scp file @mian@ip:/path
  ```
  → All use port 22.  
  The `@` symbol means “connect as user @mian to IP on port 22.”  
  SSH tools (ssh, sftp, scp) all do the same handshake: version exchange → key exchange → encryption → activity.
```



