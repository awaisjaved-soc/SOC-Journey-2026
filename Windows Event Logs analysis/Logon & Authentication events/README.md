# Logon & Authentication Events – SOC Journey 2026

Windows Security Event logs for the **Logon & Authentication** category, documented as part of the SOC Analyst learning path.

Each folder contains a dedicated README with:
- Event explanation and SOC importance
- How to generate the event (manual + PowerShell methods)
- Detection commands (PowerShell)
- SOC analyst notes and red flags

---

## Events Covered

| Event ID | Name | SOC Importance |
|----------|------|---------------|
| [4672](./Event-4672_Special-Privileges-Assigned/) | Special Privileges Assigned | 🔴 High |
| [4768](./Event-4768_Kerberos-TGT-Requested/) | Kerberos TGT Requested | 🟡 Medium |
| [4769](./Event-4769_Kerberos-Service-Ticket-Requested/) | Kerberos Service Ticket Requested | 🔴 High |
| [4771](./Event-4771_Kerberos-PreAuth-Failed/) | Kerberos Pre-Authentication Failed | 🟡 Medium |
| [4776](./Event-4776_Credential-Validation/) | Credential Validation (NTLM) | 🟡 Medium |
| [4778](./Event-4778_Session-Reconnected/) | Session Reconnected (RDP) | 🟡 Medium |
| [4779](./Event-4779_Session-Disconnected/) | Session Disconnected (RDP) | 🟡 Medium |
| [4800](./Event-4800_Workstation-Locked/) | Workstation Locked | 🟢 Low–Medium |
| [4801](./Event-4801_Workstation-Unlocked/) | Workstation Unlocked | 🟢 Low–Medium |

---

## Lab Environment

- **Domain:** TECHCORP / techcorp.local
- **Server:** WIN-KAHJ94DKN9V
- **Platform:** Windows Server (VirtualBox)
- **Test Accounts:** Administrator, scott, alexrivera

---

## Priority Reference for SOC

When triaging alerts, focus on these events first:

1. **4672** – Special Privileges (privilege escalation)
2. **4769** – Kerberos Service Tickets (Kerberoasting)
3. **4771** – Kerberos Pre-Auth Failed (brute force)
4. **4776** – NTLM Credential Validation (password attacks)
5. **4768** – Kerberos TGT (abnormal login patterns)
6. **4778/4779** – RDP Sessions (lateral movement)
7. **4800/4801** – Workstation Lock/Unlock (activity timeline)
