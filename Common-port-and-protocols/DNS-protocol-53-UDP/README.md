
# 04 - DNS Protocol (Port 53) Practical Lab

**Author:** Muhammad Awais Javed (Mian Awais)  
**Date:** April 2026  
**Part of:** SOC-Journey-2026

### What is DNS?
DNS (Domain Name System) is like the **phonebook of the internet**.  
It converts human-readable domain names (`google.com`, `youtube.com`) into machine-readable IP addresses (`142.250.190.78`).

### Why DNS Uses UDP Port 53 (While Others Use TCP)?

- **UDP** is used because:
  - DNS queries are very small and fast.
  - Speed is more important than perfect reliability for normal lookups.
  - If no response comes, the client automatically retries.

- **TCP** is used only when:
  - Response is very large (>512 bytes)
  - Zone Transfer (AXFR) between DNS servers

**SOC Importance**: DNS is heavily abused by attackers for **DNS Tunneling**, Command & Control (C2), and data exfiltration. SOC analysts monitor port 53 very closely.

### Topics Covered
- How DNS resolution works
- Difference between UDP and TCP in DNS
- DNS Query types (A, AAAA, MX, NS, etc.)
- Wireshark analysis of DNS traffic
- Practical DNS server setup and querying

### Tools Used
- Kali Linux
- Wireshark
- dig command
- Python DNS server (for debugging)

### Practicals Completed
- Set up a simple DNS server
- Performed DNS queries from another device
- Captured DNS traffic in Wireshark (UDP port 53)
- Analyzed query/response packets
- Understood how easy it is to see which websites someone is visiting

### Key Learning
- DNS is fast because it uses UDP by default.
- Everything in normal DNS queries is in **plain text** (no encryption).
- This makes DNS a high-value protocol for both defenders and attackers.

**SOC Takeaway**:  
Monitoring DNS traffic is one of the most important tasks in SOC. Suspicious domains, high query volume, and DNS tunneling are common red flags.

---
