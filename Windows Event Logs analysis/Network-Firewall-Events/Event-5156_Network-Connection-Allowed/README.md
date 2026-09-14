# Event ID 5156 — Network Connection Allowed

**Log:** Security  
**Category:** Object Access  
**Subcategory:** Filtering Platform Connection  
**Level:** Information  
**Lab Environment:** Windows Server 2022 — TECHCORP / techcorp.local  
**Lab Status:** ✅ Successfully Generated

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 5156 |
| Event Name | The Windows Filtering Platform has permitted a connection |
| Log Location | Windows Logs → Security |
| Audit Subcategory | Filtering Platform Connection |
| Default State | Disabled — must be manually enabled |
| SACL Required | No |
| Volume | Very High — fires for every allowed network connection |

---

## Understanding Windows Filtering Platform (WFP)

Windows Filtering Platform is the kernel-level network filtering engine built into Windows. Every single network packet that enters or leaves a Windows machine passes through WFP before anything else touches it. WFP checks each packet against its ruleset — firewall rules, connection security rules, and other filters — and makes a decision: allow or block.

Event 5156 is WFP's record of every connection it decided to allow. This makes it the most comprehensive network visibility event in Windows — but also the noisiest. On any active machine, especially a Domain Controller running Kerberos, LDAP, DNS, and RDP simultaneously, Event 5156 fires hundreds to thousands of times per minute from legitimate Windows activity.

The value of 5156 in SOC work is not in alerting on every event — it is in **filtering for anomalies**. Known good processes making connections to known destinations are background noise. Unknown processes, unusual destination IPs, unexpected ports, or connections happening at 3 AM when the machine should be idle — those are the signals.

---

## What Event 5156 Captures

Every 5156 event contains the complete five-tuple of the allowed connection:

- **Process** — which executable made or received the connection
- **Direction** — outbound (machine initiated) or inbound (external machine connected)
- **Source IP and Port** — where the connection came from
- **Destination IP and Port** — where the connection went
- **Protocol** — TCP (6) or UDP (17)

This combination is what makes 5156 powerful for C2 detection. When malware on a compromised machine connects to an attacker's server, 5156 records the exact process, destination IP, and port — everything needed to identify and block the channel.

### Important Note on Volume — Domain Controllers

On a Domain Controller, `lsass.exe` generates massive numbers of 5158 and 5156 events because it handles all Kerberos authentication. Every ticket request, every LDAP query, every domain authentication opens and closes sockets. When running detection commands, always filter by specific process names or port numbers rather than reviewing raw output.

---

## Audit Policy Setup

### Command Line

```cmd
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

### Verify

```cmd
auditpol /get /subcategory:"Filtering Platform Connection"
```

> ⚠️ After completing the lab, disable this auditing to prevent log flooding:
> ```cmd
> auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:disable
> ```

---

## Generating the Event

### Method 1 — Browser or Web Request (Simplest)

Open any browser and visit any website. Each page load generates multiple 5156 events — one for DNS resolution, one for the TCP connection, sometimes more.

### Method 2 — PowerShell Web Request

```powershell
# Outbound HTTPS connection to Google DNS — clean and reliable
Invoke-WebRequest -Uri "https://www.google.com" -UseBasicParsing | Select-Object StatusCode

# Direct TCP connection to Google DNS on port 53
Test-NetConnection -ComputerName 8.8.8.8 -Port 53

# Simulate C2-like outbound connection pattern
Test-NetConnection -ComputerName 1.1.1.1 -Port 443

Write-Host "Connections made. Check Security log for Event 5156." -ForegroundColor Green
```

### Method 3 — Listener + Loopback (Best Lab Setup)

This creates both a server (listener) and client (connection) on the same machine, giving you full control of both sides:

```powershell
# === WINDOW 1 — Start the listener (simulates backdoor) ===
$listener = [System.Net.Sockets.TcpListener]::new(
    [System.Net.IPAddress]::Any, 7777
)
$listener.Start()
Write-Host "Listener running on port 7777." -ForegroundColor Green
Write-Host "Now connect from Window 2."

# === WINDOW 2 — Connect to it ===
Test-NetConnection -ComputerName 127.0.0.1 -Port 7777
# TcpTestSucceeded : True confirms the connection was allowed and 5156 fired

# After screenshot — stop the listener in Window 1
$listener.Stop()
Write-Host "Listener stopped." -ForegroundColor Green
```

---

## Detecting the Event

### GUI — Event Viewer

1. Event Viewer → Windows Logs → **Security**
2. Filter Current Log → Event ID: `5156` → OK
3. Look for entries timestamped when you ran your commands
4. Check Application field — `powershell.exe` connections stand out from system noise

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Application Name | Process making the connection — unexpected processes are suspicious |
| Direction | `%%14592` = Outbound / `%%14593` = Inbound |
| Source Address | Your machine IP |
| Source Port | Random high port for outbound / your listener port for inbound |
| Destination Address | Where the connection went — external IPs are most interesting |
| Destination Port | 80/443 from unknown processes, unusual high ports from any process |
| Protocol | 6 = TCP / 17 = UDP |

### PowerShell Detection

```powershell
# Last 10 allowed connections
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 5156
} -MaxEvents 10 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        Application = ($data | Where-Object { $_.Name -eq 'Application'   }).'#text'
        Direction   = ($data | Where-Object { $_.Name -eq 'Direction'     }).'#text'
        SourceIP    = ($data | Where-Object { $_.Name -eq 'SourceAddress' }).'#text'
        SourcePort  = ($data | Where-Object { $_.Name -eq 'SourcePort'    }).'#text'
        DestIP      = ($data | Where-Object { $_.Name -eq 'DestAddress'   }).'#text'
        DestPort    = ($data | Where-Object { $_.Name -eq 'DestPort'      }).'#text'
        Protocol    = ($data | Where-Object { $_.Name -eq 'Protocol'      }).'#text'
    }
} | Format-Table -AutoSize
```

```powershell
# Filter for your specific lab connection — by destination IP
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 5156
    StartTime = (Get-Date).AddMinutes(-30)
} | Where-Object {
    $_.Message -like "*8.8.8.8*" -or
    $_.Message -like "*1.1.1.1*" -or
    $_.Message -like "*7777*"
} | Select-Object TimeCreated, Message | Format-List
```

```powershell
# Hunt for suspicious outbound connections — filter by process
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 5156
    StartTime = (Get-Date).AddHours(-1)
} | Where-Object {
    $_.Message -like "*powershell*" -or
    $_.Message -like "*cmd.exe*"   -or
    $_.Message -like "*wscript*"
} | ForEach-Object {
    Write-Host "=== SUSPICIOUS OUTBOUND CONNECTION ===" -ForegroundColor Red
    Write-Host "Time    : $($_.TimeCreated)"
    Write-Host "Details : $($_.Message)"
}
```

---

## SOC Analyst Notes

### Normal vs Suspicious 5156 Patterns

| Pattern | Verdict |
|---|---|
| `svchost.exe` connecting to Microsoft IPs on 80/443 | Normal — Windows Update, telemetry |
| `lsass.exe` connecting on high ports — DC only | Normal — Kerberos authentication |
| Browser process connecting to external IPs on 443 | Normal — web browsing |
| `powershell.exe` outbound to unknown external IP at 3 AM | **Investigate — possible C2** |
| Any process connecting to known malicious IP | **Critical alert** |
| Process connecting to internal IP on unusual port | **Lateral movement indicator** |

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Known process, known destination, business hours |
| 🟡 Medium | PowerShell making outbound connections |
| 🔴 High | Unknown process, external IP, unusual port |
| 🔴 Critical | Known C2 IP or domain, any process |

### MITRE ATT&CK Reference

- **T1071** — Application Layer Protocol (C2 over HTTP/HTTPS)
- **T1571** — Non-Standard Port
- **T1090** — Proxy (traffic routing through internal hosts)
