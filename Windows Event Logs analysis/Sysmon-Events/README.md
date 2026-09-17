# Sysmon Events (Category 8)

**Part of:** SOC-Journey-2026  
**Author:** Muhammad Awais Javed  
**Lab Environment:** Windows Server 2022 — TECHCORP.local

---

## What is Sysmon?

System Monitor (Sysmon) is a free Microsoft Sysinternals tool that provides detailed system activity logging far beyond native Windows Event Logs.

It runs as a Windows service and writes events to:

**Microsoft-Windows-Sysmon/Operational**

### Why Sysmon is important for SOC

| Native Windows Event | Sysmon Advantage |
|----------------------|------------------|
| 4688 (Process Create) | Event 1 includes full CommandLine, ParentProcess, Hashes |
| Limited network visibility | Event 3 shows process + network connection |
| No DNS process link | Event 22 links DNS query to the exact process |
| Limited file create detail | Event 11 shows which process created the file |

---

## Events Covered in This Category

| Sysmon ID | Name                | Status |
|-----------|---------------------|--------|
| 1         | Process Creation    | Pending |
| 3         | Network Connection  | Pending |
| 7         | Image Loaded (DLL)  | Pending |
| 10        | Process Access      | Pending |
| 11        | File Create         | ✅ Done |
| 22        | DNS Query           | ✅ Done |

---

## Folder Structure

- `Sysmon-Setup/` → Installation & configuration guide
- `Event-11_File-Create/` → File creation lab
- `Event-22_DNS-Query/` → DNS query lab

---

**Goal:** Learn the most important Sysmon events used daily in real SOC environments.
