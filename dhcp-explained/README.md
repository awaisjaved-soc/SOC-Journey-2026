**DHCP (Dynamic Host Configuration Protocol) is a client–server protocol that automatically assigns IP addresses and other network settings to devices, eliminating the need for manual configuration. It works through a four-step process called DORA (Discover, Offer, Request, Acknowledge).**  

---

## 🌐 What DHCP Does
- **Assigns IP addresses** dynamically from a pool.  
- **Provides subnet mask** to define the local network range.  
- **Configures default gateway** for communication outside the LAN.  
- **Supplies DNS server addresses** for domain name resolution.  
- **Sets lease time** (how long a device can use the assigned IP).  

---

- DHCP uses UDP 
- Port 67 is for server
- Port 68 is for client

## ⚙️ DHCP Components
- **DHCP Server**: Usually a router or dedicated server; maintains the IP pool.  
- **DHCP Client**: Any device (PC, phone, printer) requesting an IP.  
- **IP Address Pool**: Range of available IPs the server can assign.  
- **Lease**: Temporary assignment of an IP to a client.
---

## 🔄 DHCP Workflow (DORA)
The process has **four key steps**:

1. **Discover**  
   - Client broadcasts a request to find DHCP servers.  
   - Source IP: `0.0.0.0` (no IP yet).  
   - Destination: `255.255.255.255` (broadcast).  

2. **Offer**  
   - DHCP server responds with an available IP address, subnet mask, gateway, DNS, and lease time.  

3. **Request**  
   - Client requests the offered IP formally.  

4. **Acknowledge**  
   - Server confirms and finalizes the lease.  
   - Client configures itself with the provided settings.  

---

## 📦 Example: DHCP in Action
- You connect a laptop to Wi-Fi.  
- The laptop sends a **Discover** message.  
- Router (DHCP server) replies with an **Offer** (e.g., `192.168.1.25`).  
- Laptop sends a **Request** for that IP.  
- Router sends an **Acknowledge**, and now your laptop can communicate on the network.  

---

## 🔑 Advantages
- **Automation**: No need to manually assign IPs.  
- **Consistency**: Prevents conflicts by tracking leases.  
- **Flexibility**: Works across LANs, WLANs, and enterprise networks.  
- **Scalability**: Handles hundreds or thousands of devices easily.  

---

## ⚠️ Limitations
- **Single point of failure**: If DHCP server goes down, new devices can’t get IPs.  
- **Security risks**: Rogue DHCP servers can assign malicious IPs.  
- **Lease expiration**: Devices may lose connectivity if renewal fails.  

---

## 📚 Related Concepts
- **Static IP**: Manually configured, doesn’t change.  
- **NAT (Network Address Translation)**: Works with DHCP to allow multiple private IPs to share one public IP.  
- **RFC 2131**: Defines DHCP standards.  

---
