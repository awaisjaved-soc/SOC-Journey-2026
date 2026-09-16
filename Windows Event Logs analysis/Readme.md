
# Windows Event Logs Analysis

**Part of:** SOC-Journey-2026  
**Author:** Muhammad Awais Javed  
**Focus:** Core SOC Skill — Understanding and Analyzing Windows Security Events

---

### 📌 Introduction

This folder contains my hands-on practical labs and notes on **Windows Event Logs** — one of the most important skills for any SOC Analyst.

Windows Event Logs are the main source of information that SOC teams monitor 24/7. Almost every alert in SIEM tools (Wazuh, Splunk, Sentinel, etc.) comes from these logs.

### What I Am Learning Here:
- How to enable proper auditing
- Generating real security events
- Reading and analyzing critical Event IDs
- Understanding normal vs suspicious behavior
- Real-world SOC investigation techniques
- Common attack patterns and their logs

---

### 📂 Folder Structure & Current Progress

| Category | Folder | Status | Key Events |
|----------|--------|--------|------------|
| 1. Logon & Authentication | Logon & Authentication events | ✅ Completed | 4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769, 4771, 4776, 4778, 4779, 4800, 4801 |
| 2. Account Management | Account Management Events | ✅ Completed | 4720, 4722, 4723, 4724, 4725, 4726, 4727, 4728, 4729, 4730, 4731, 4737, 4738, 4740, 4741, 4742, 4743, 4755, 4756, 4757, 4767, 4781 |
| 3. Process & System Events | Process-and-System-Events | ✅ Completed | 4688, 4689, 4103, 4104, 4697, 4698–4702, 7045, 5857–5861, 6005, 6006, 6008 + more |
| 4. Audit & Log Tampering | Audit Log Tampering | ✅ Completed | 1100, 1102, 4706, 4707, 4713, 4719, 4739, 4906, 4907 |
| 5. PowerShell & Scripts | (Inside Category 3) | ✅ Completed | 4103, 4104 |
| 6. Network & Firewall | Network-Firewall-Events | ✅ Completed | 5156, 5157, 5152, 5154, 5158, 4946, 4947, 4948, 4954 |
| 7. Privilege Use | Privilege Use Events | ✅ Completed | 4673, 4674 |
| 8. Sysmon Events | — | 🔄 Current | 1, 3, 7, 10, 11, 22 |

---

### Learning Approach

I focus on deep practical understanding rather than only theory:
- Enable proper auditing
- Generate real security events
- Analyze them in Event Viewer + PowerShell
- Understand normal vs suspicious behavior
- Document everything properly on GitHub

---

### Goal

Build strong foundational knowledge to investigate real incidents, detect attacks early, and think like a professional SOC Analyst (L1).

**Currently working on:** Sysmon Events

*Last Updated: September 2026*

---

