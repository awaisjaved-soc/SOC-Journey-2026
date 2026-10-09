# 🌐 DHCP — Port 67/68 | Practical Lab

**Author:** Muhammad Awais Javed (Mian Awais) / **Date:** May 2026 / **Part of:** [SOC-Journey-2026](https://github.com/awaisjaved-soc/SOC-Journey-2026)

---

## 📌 Table of Contents

- [🎯 Objective](#-objective)
- [📖 What is DHCP?](#-what-is-dhcp)
- [⚙️ How It Works](#️-how-it-works)
- [🧪 Lab Environment](#-lab-environment)
- [💻 Commands Used](#-commands-used)
- [🔍 Wireshark Analysis](#-wireshark-analysis)
- [🚨 SOC Analyst Notes](#-soc-analyst-notes)
- [🛡️ MITRE ATT&CK](#️-mitre-attck)
- [📸 Screenshots](#-screenshots)
- [✅ Key Takeaways](#-key-takeaways)

> 🔬 This is the **theory companion** to the hands-on work. For the practical labs, see [`dhcp-practical`](../dhcp-practical/) — DORA in Wireshark, a Cisco Packet Tracer DHCP server build, and a live rogue-DHCP attack.

---

## 🎯 Objective

To understand how devices get their IP addresses automatically — the protocol, the ports, the four-step DORA handshake, and what a DHCP conversation looks like at the packet level — so that later I can recognize when something on the network is answering DHCP who shouldn't be.

---

## 📖 What is DHCP?

**DHCP (Dynamic Host Configuration Protocol)** is a client–server protocol that automatically assigns IP addresses and other network settings to devices, eliminating the need for manual configuration. It is defined in **RFC 2131**.

### 🌐 What DHCP hands out

| Setting | Purpose |
|---------|---------|
| **IP address** | Assigned dynamically from a pool |
| **Subnet mask** | Defines the local network range |
| **Default gateway** | Route for traffic leaving the LAN |
| **DNS servers** | Addresses for domain-name resolution |
| **Lease time** | How long the device may keep the IP |

### 🔌 Ports and transport

- DHCP runs over **UDP** (connectionless — the client has no IP yet, so TCP handshakes are impossible).
- **Port 67** → DHCP **server**
- **Port 68** → DHCP **client**

### ⚙️ DHCP components

- **DHCP Server** — usually a router or dedicated server; owns and manages the IP pool.
- **DHCP Client** — any device (PC, phone, printer) requesting an address.
- **IP Address Pool** — the range of addresses the server may hand out.
- **Lease** — a temporary assignment of an IP to a client; it expires and must be renewed.

### 📦 Example: DHCP in action

1. You connect a laptop to Wi-Fi.
2. The laptop sends a **Discover** message.
3. The router (DHCP server) replies with an **Offer** (e.g. `192.168.1.25`).
4. The laptop sends a **Request** for that IP.
5. The router sends an **Acknowledge** — and now your laptop can communicate on the network.

---

## ⚙️ How It Works

### 🔄 The DORA handshake

Every DHCP lease is negotiated in four steps:

**1. Discover**
- The client broadcasts to find DHCP servers.
- Source IP: `0.0.0.0` (it has no IP yet) → Destination: `255.255.255.255` (broadcast).
- Sent from UDP port 68 to UDP port 67.

**2. Offer**
- Each DHCP server on the network replies with an available IP, subnet mask, gateway, DNS servers, and lease time.
- ⚠️ *If more than one server answers, the client normally takes the first offer it receives — this is exactly what makes rogue-DHCP attacks possible.*

**3. Request**
- The client formally requests the offered IP (broadcast again, so all servers see which offer was accepted and can withdraw theirs).

**4. Acknowledge (ACK)**
- The chosen server confirms and finalizes the lease.
- The client configures its IP, mask, gateway, and DNS — and it's on the network.

### 🔁 Lease lifecycle

A lease isn't forever: the client tries to **renew** it (unicast to the server) at 50% of the lease time, and **rebind** (broadcast) at 87.5% if renewal fails. `ipconfig /release` gives the address back early — you'll see the source drop to `0.0.0.0` in Wireshark right after.

---

## 🧪 Lab Environment

This folder is theory; the hands-on labs live in [`dhcp-practical`](../dhcp-practical/):

| Lab | What I did |
|-----|-------------|
| DORA in Wireshark | `ipconfig /release` + `/renew` on a live machine, captured the full handshake |
| Cisco Packet Tracer | Built a DHCP server on a Cisco router with two pools (`192.168.100.0/24`, `192.168.200.0/24`) |
| Rogue DHCP attack | Ran a rogue `isc-dhcp-server` and hijacked a victim phone's gateway |

---

## 💻 Commands Used

```cmd
ipconfig
```
Shows the current IP configuration — the "before" picture before releasing the lease. (On Linux: `iwconfig` / `ip addr`.)

```cmd
ipconfig /release
```
Gives up the current IP. The machine sends a DHCP **Release** packet, the server marks the IP free, and the device drops to `0.0.0.0`.

```cmd
ipconfig /renew
```
Triggers the full **DORA** handshake — Discover → Offer → Request → ACK — and the device comes back with a fresh lease.

---

## 🔍 Wireshark Analysis

**Display filter:**
```
udp.port == 67 or udp.port == 68
```

**What to look for:**

| Packet | Source → Destination | Tells you |
|--------|---------------------|-----------|
| Discover | `0.0.0.0` → `255.255.255.255` | A device with no IP shouting for a server |
| Offer | server IP → `255.255.255.255` | The offered address, mask, gateway, DNS, lease time |
| Request | `0.0.0.0` → `255.255.255.255` | Which offer the client accepted |
| ACK | server IP → `255.255.255.255` | Lease confirmed |

Open the Offer/ACK packets and expand the **DHCP options** — Option 51 (lease time), Option 1 (subnet mask), Option 3 (router/gateway), Option 6 (DNS). In the rogue-DHCP lab, Option 3 is the smoking gun: it points at the attacker instead of the real router.

---

## 🚨 SOC Analyst Notes

**How attackers abuse DHCP:**

- **Rogue DHCP server** — an unauthorized server answers Discovers faster than the legitimate one and hands out a malicious gateway/DNS, putting the attacker in a full man-in-the-middle position. I built this attack live in [`dhcp-practical`](../dhcp-practical/) — it works.
- **DHCP starvation** — flooding the server with fake Discover messages to exhaust the pool, denying addresses to legitimate clients (a DoS against onboarding).
- **Malicious DNS via DHCP** — even without full MITM, handing out an attacker-controlled DNS server enables phishing and traffic redirection.

**What to monitor:**

- **Multiple DHCP Offers** for a single Discover — more than one server answering is the classic rogue indicator.
- Sudden **gateway or DNS changes** on endpoints (Option 3 / Option 6 differing from the known-good values).
- Devices receiving IPs from **unexpected ranges**.
- DHCP servers appearing on **unexpected MACs/ports** — legitimate servers are known infrastructure; anything else is suspect.

**Defenses:** DHCP snooping on switches (only trusted ports may send server messages), Dynamic ARP Inspection, and 802.1X/NAC so rogue devices can't join the LAN in the first place.

---

## 🛡️ MITRE ATT&CK

| Technique | ID | Relevance |
|-----------|----|-----------|
| Adversary-in-the-Middle | **T1557** | Rogue DHCP makes the attacker the gateway — full MITM |
| Network Denial of Service | **T1498** | DHCP starvation exhausts the address pool |
| Traffic Duplication* | — | Rogue DNS/gateway silently redirects victim traffic |

*Covered under T1557 sub-techniques depending on method.

---

## 📸 Screenshots

The captures for this topic live with the practical labs:

| Capture | File |
|---------|------|
| DORA handshake in Wireshark | [`../dhcp-practical/DHCP-DORA-process/dora-process.png`](../dhcp-practical/DHCP-DORA-process/dora-process.png) |
| Cisco Packet Tracer DHCP topology | [`../dhcp-practical/DHCP-Lab-CiscoPacketTracer/dhcp-lab.png`](../dhcp-practical/DHCP-Lab-CiscoPacketTracer/dhcp-lab.png) |
| Victim phone on the rogue lease | [`../dhcp-practical/DHCP-ROGUE/attacked-device.jpeg`](../dhcp-practical/DHCP-ROGUE/attacked-device.jpeg) |

---

## ✅ Key Takeaways

- DHCP automates IP assignment over **UDP ports 67 (server) / 68 (client)** through the **DORA** handshake — Discover (`0.0.0.0` → broadcast) → Offer → Request → ACK.
- The client accepts the **first** Offer it receives. That single design fact is what makes rogue-DHCP attacks possible — whoever answers fastest wins.
- In Wireshark, `udp.port == 67 or udp.port == 68` shows the whole conversation; DHCP **Option 3 (gateway)** and **Option 6 (DNS)** are where an attacker's fingerprints show up.
- Advantages are real (automation, no conflicts, scale) but so are the risks: single point of failure, lease-expiry outages, and rogue servers — which is why DHCP snooping exists.
