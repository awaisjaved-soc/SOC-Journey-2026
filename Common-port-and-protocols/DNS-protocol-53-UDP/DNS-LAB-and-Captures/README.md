
```markdown
# 04 - DNS Protocol (Port 53) Practical Lab

**Author:** Muhammad Awais Javed (Mian Awais)  
**Date:** April 2026  
**Part of:** SOC-Journey-2026

### Objective
To understand how DNS works in real life by setting up my own DNS server, querying it from another device, and analyzing the traffic in Wireshark.

### What is DNS?
DNS (Domain Name System) is the "phonebook of the internet". It converts human-readable domain names (`google.com`) into IP addresses (`142.250.190.78`).

### Why DNS Uses UDP Port 53?
- **UDP** is fast and has low overhead — perfect for small, quick DNS queries.
- If no response comes, the client automatically retries.
- TCP is used only for large responses or zone transfers.

**SOC Importance**: DNS is heavily monitored because attackers use it for C2 communication, tunneling, and data exfiltration.

### Tools Used
- Kali Linux (dnsmasq)
- Wireshark
- dig / nslookup
- Two devices (PC VM + Laptop)

### A to Z Practical Steps

#### 1. On DNS Server (Kali VM - 192.168.100.91)

```bash
sudo apt update
sudo apt install dnsmasq -y
```

**Configuration:**
```bash
sudo nano /etc/dnsmasq.conf
```

Added at the bottom:
```conf
no-resolv
server=8.8.8.8
listen-address=192.168.100.91
address=/google.test/192.168.100.91
address=/facebook.test/192.168.100.91
address=/instagram.test/192.168.100.91
```
You can add whatever you want this is only for the testing and checking how the dns works.And when you use real domain like google.com it will forward you to the real server.

```bash
sudo systemctl restart dnsmasq
sudo ss -tuln | grep :53
```

#### 2. On Client (Linux Laptop - 192.168.100.90)

```bash
sudo nano /etc/resolv.conf
```
Changed to:
```conf
nameserver 192.168.100.91
```

#### 3. Testing DNS Queries (from Laptop)

```bash
dig google.test
dig facebook.test
dig instagram.test
dig wikipedia.com
```

#### 4. Capturing DNS Traffic in Wireshark (on PC VM)

- Interface: `eth0`
- Capture filter: `udp port 53 or tcp port 53`
- Queried real and custom domains from laptop
- Analyzed queries and responses

### Key Learnings
- DNS queries are mostly UDP and in plain text.
- Custom domains return our own IP.
- Real domains are forwarded to 8.8.8.8 and return real IPs.
- Easy to see which websites a user is visiting by monitoring DNS traffic.
- SOC analysts monitor port 53 for suspicious domains and tunneling.

