# 🌐 Common Ports & Protocols — Practical Labs

**Author:** Muhammad Awais Javed (Mian Awais)
**Part of:** [SOC-Journey-2026](https://github.com/awaisjaved-soc/SOC-Journey-2026)

Every protocol a SOC analyst meets on the wire — each in its own folder with the theory, a hands-on lab I built, the exact commands, Wireshark captures, and SOC analyst notes on how attackers abuse it.

## 📌 Protocol Index

| # | Protocol | Port | Folder | Highlights |
|---|----------|------|--------|------------|
| 01 | DNS | 53/UDP | [Open](./DNS-protocol-53-UDP) | dnsmasq lab, `dig` tests, tunneling & DGA detection |
| 02 | FTP | 21/TCP | [Open](./FTP-protocol) | vsftpd anonymous login, plaintext credential capture |
| 03 | SSH / SFTP | 22/TCP | [Open](./Secure-shell-SSH-SFTP-port-22) | OpenSSH setup, SCP/SFTP, Fail2Ban brute-force defense |
| 04 | SMTP / Telnet | 25/TCP | [Open](./SMTP-TELNET-port-25) | Postfix lab, raw Telnet mail session, spoofing |
| 05 | HTTP | 80/TCP | [Open](./HTTP-port-80-tcp) | Apache + PHP login form, plaintext password capture |
| 06 | Kerberos | 88/TCP+UDP | [Open](./kerberos-port88) | KDC lab, `kinit`/`klist`, pass-the-ticket, Kerberoasting |
| 07 | LDAP | 389/TCP | [Open](./LDAP-TCP-389) | OpenLDAP queries, AD enumeration, brute-force loop |
| 08 | LDAP on Windows Server | 389/TCP | [Open](./LDAP-USING-WINDOWS-SERVER) | Full AD domain build, 12 users, attack chain |
| 09 | HTTPS | 443/TCP | [Open](./Https-443-tcp) | Self-signed TLS, handshake analysis, JA3/SNI notes |
| 10 | SMB | 445/TCP | [Open](./SMB-protocol-tcp-445) | Samba share build, SMB3 encryption, null sessions |
| 11 | RDP | 3389/TCP | [Open](./RDP-TCP-3389) | RDP enablement, Hydra brute-force, NLA notes |
| 12 | DHCP | 67-68/UDP | [Open](./dhcp-explained) · [Practical](./dhcp-practical) | DORA process, Packet Tracer build, rogue DHCP attack |

## 🧰 How I Work Each Protocol

1. **Theory** — what it is, how it works at the packet level
2. **Lab** — I build it (server + client, usually Kali ↔ Windows/Linux)
3. **Capture** — Wireshark, with display filters documented
4. **Attack** — where relevant, I abuse it the way an attacker would
5. **Defend** — what a SOC analyst should monitor, alert on, and hunt for

> Every folder follows the same structure: Objective → Theory → Lab → Commands → Wireshark → SOC Notes → MITRE ATT&CK → Screenshots → Takeaways.
