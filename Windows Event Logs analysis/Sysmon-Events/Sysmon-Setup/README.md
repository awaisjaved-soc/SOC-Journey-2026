# Sysmon Installation & Setup Guide

**Lab Environment:** Windows Server 2022 — TECHCORP.local  
**Status:** ✅ Successfully Installed

---

## What is Sysmon?

System Monitor (Sysmon) is a free Microsoft Sysinternals tool that provides high-quality system logging. It runs as a Windows service and logs detailed activity to its own channel:

**Microsoft-Windows-Sysmon/Operational**

### Why Sysmon is better than native logs

- Native Event 4688 often misses full command line
- Sysmon Event 1 captures full CommandLine + Parent Process + Hashes
- Sysmon logs network connections, DNS queries, file creates, and process access with much richer context

---

## Step 1 — Download Sysmon

Download from official Microsoft page:

https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

Or direct link:

https://download.sysinternals.com/files/Sysmon.zip

Extract the zip. You will get:

- `Sysmon64.exe` ← Use this one (64-bit)
- Sysmon.exe (32-bit)
- Sysmon64a.exe (ARM)

---

## Step 2 — Get a Good Configuration File

Sysmon without a proper config is almost useless.

**Recommended config (industry standard):**

SwiftOnSecurity Sysmon Config  
https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml

Save it as `sysmonconfig.xml`

Recommended folder structure:

```
C:\Sysmon\
    Sysmon64.exe
    sysmonconfig.xml
```

---

## Step 3 — Install Sysmon

Open PowerShell as Administrator:

```powershell
cd C:\Sysmon

.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

**Flags meaning:**
- `-accepteula` → Accepts the license automatically
- `-i` → Install with the given config file

Expected output includes:

```
Sysmon64 installed.
SysmonDrv installed.
Starting SysmonDrv.
SysmonDrv started.
Starting Sysmon64.
Sysmon64 started.
```

---

## Step 4 — Verify Installation

```powershell
# Check service
Get-Service Sysmon64

# Check driver
Get-Service SysmonDrv

# View current config
.\Sysmon64.exe -c
```

---

## Step 5 — Verify Events Are Flowing

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 |
Select-Object TimeCreated, Id, Message | Format-List
```

Also check in Event Viewer:

```
Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
```

---

## Useful Management Commands

```powershell
# Update config without reinstalling
.\Sysmon64.exe -c sysmonconfig.xml

# Uninstall Sysmon
.\Sysmon64.exe -u

# Check version
.\Sysmon64.exe --version
```

---

## Quick Smoke Tests

```powershell
# Test Event ID 1
Start-Process notepad.exe

# Test Event ID 22
Resolve-DnsName google.com

# Test Event ID 11
New-Item -Path "C:\Temp\sysmon_test.txt" -ItemType File -Force
```

Then check the corresponding Event IDs in the Sysmon Operational log.
