# 04 - DNS Protocol (Port 53) Practical Lab

**Author:** Muhammad Awais Javed  
**Date:** April 2026  
**Part of:** SOC-Journey-2026

### What is DNS?
DNS (Domain Name System) is the "phonebook of the internet".  
It converts human-readable domain names (`google.com`) into machine-readable IP addresses (`142.250.190.78`).

### Why DNS Uses UDP Port 53 (While Others Use TCP)?

**TCP = Reliable Delivery**  
- Does handshake, acknowledgment, retransmission if packet is lost, ordering, etc.  
- Good for: File transfer, email, web pages (where losing data is bad).

**UDP = Fast but Not Guaranteed**  
- No handshake, no acknowledgment, no retransmission.  
- Good for: Real-time things like video calls, online gaming, and **DNS** (where speed matters more than perfect reliability).

### Why DNS Uses UDP?

1. **DNS queries are very small**  
   A normal DNS query + response is usually under 512 bytes. Losing one small packet is not a big problem.

2. **Speed is critical**  
   Every time you open a website, a DNS query happens. If it used TCP (with 3-way handshake), the internet would feel much slower.

3. **Built-in Reliability**  
   If no response comes within 1-2 seconds, the client automatically retries the query. It can also switch to another DNS server (e.g., from 8.8.8.8 to 1.1.1.1).

4. **When DNS Uses TCP**  
   - When response is very large (>512 bytes)  
   - For Zone Transfers (copying entire DNS database between servers)

### Real-World Example
- You type `google.com`
- Your PC sends a small UDP packet to DNS server on port 53 asking "What is the IP of google.com?"
- DNS server replies with UDP packet containing the IP.
- If no reply comes in 1 second → your PC automatically retries.

### SOC Perspective
- Most DNS traffic in SOC is **UDP port 53**.
- Attackers heavily abuse DNS for **DNS Tunneling**, C2 communication, and data exfiltration because it is fast and often poorly monitored.
- SOC analysts monitor port 53 very closely for suspicious domains and abnormal query patterns.

### Tools Used
- Kali Linux (dnsmasq)
- Wireshark
- dig / nslookup

### Key Learnings
- DNS is fast because it uses UDP by default.
- Normal DNS queries are in **plain text**.
- Custom domains return our own IP, real domains are forwarded to upstream DNS.

