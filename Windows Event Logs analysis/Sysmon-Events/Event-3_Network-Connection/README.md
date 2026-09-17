# Sysmon Event ID 3 – Network Connection

## Overview

| Field        | Details                              |
|--------------|--------------------------------------|
| **Event ID** | 3                                    |
| **Category** | Process & System Events              |
| **Name**     | Network Connection                   |
| **Log**      | Microsoft-Windows-Sysmon/Operational |
| **Importance** | High                               |

---

## What Is Event ID 3?

**Event ID 3 (Network Connection)** is generated whenever a process initiates a network connection (TCP or UDP).

This is one of the most valuable Sysmon events for SOC analysts because it ties network traffic directly to the process that caused it. Standard network logs show IPs and ports, but they don't tell you which program made the connection. Sysmon bridges that gap.

This event helps detect:
- Command & Control (C2) communication
- Malware calling home
- Suspicious outbound connections from unexpected processes
- Lateral movement attempts
- Data exfiltration

---

## Key Fields

| Field              | Meaning                                          |
|--------------------|--------------------------------------------------|
| `Image`            | The process that initiated the connection        |
| `User`             | User account that owns the process               |
| `Protocol`         | tcp or udp                                       |
| `SourceIp`         | Source IP address of the connection              |
| `SourcePort`       | Source port number                               |
| `DestinationIp`    | Destination IP address                           |
| `DestinationPort`  | Destination port number                          |
| `DestinationHostname` | Destination hostname (if resolved)            |
| `Initiated`        | Whether the connection was initiated (outbound)  |

---

## How to Generate Event ID 3

### Method 1: GUI

1. Open a browser (Chrome/Edge) and visit any website
2. Open Command Prompt and ping a domain:
   ```cmd
   ping google.com
   ```

### Method 2: PowerShell (Recommended)

```powershell
# Generate network connection events
Test-NetConnection -ComputerName google.com -Port 443
Test-NetConnection -ComputerName 8.8.8.8 -Port 53
Invoke-WebRequest -Uri "https://www.example.com" -UseBasicParsing
```

---

## Detection Commands

### Basic View

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=3]]" -MaxEvents 10 |
Select-Object TimeCreated, Id, Message | Format-List
```

### Detailed View (Recommended)

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=3]]" -MaxEvents 8 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time            = $_.TimeCreated
        Process         = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'}).'#text'
        User            = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'}).'#text'
        Protocol        = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Protocol'}).'#text'
        SourceIP        = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SourceIp'}).'#text'
        SourcePort      = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SourcePort'}).'#text'
        DestinationIP   = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DestinationIp'}).'#text'
        DestinationPort = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DestinationPort'}).'#text'
    }
} | Format-Table -AutoSize -Wrap
```

---

## Normal vs Suspicious Activity

| Indicator            | Normal Example                                  | Suspicious Example                                      |
|----------------------|-------------------------------------------------|---------------------------------------------------------|
| **Process**          | `chrome.exe`, `svchost.exe`, `powershell.exe`   | `notepad.exe`, `calc.exe`, unknown `.exe` making connections |
| **Destination port** | 80, 443 (web traffic), 53 (DNS)                 | High/unusual ports (4444, 1337, 8080, 9999)             |
| **Destination IP**   | Known services (Google, Microsoft CDN)          | Unknown IP addresses, especially non-standard ports     |
| **Protocol**         | tcp on 443 (HTTPS)                              | Raw TCP on unusual ports                                |

---

## SOC Analyst Notes

When analyzing Event ID 3, ask yourself:

1. **Should this process be making a network connection?** `notepad.exe` or `calc.exe` connecting anywhere is immediately suspicious.
2. **Is the destination IP known or expected?** Unknown external IPs, especially on unusual ports, deserve investigation.
3. **Is this a known C2 port?** Common C2 ports include 4444 (Metasploit), 1337, 8080, 9999, and other non-standard ports.
4. **Is it connecting to an IP directly instead of a hostname?** Malware sometimes avoids DNS and connects directly to IPs to evade DNS-based detection.

---

## Key Takeaways

- Event ID 3 = A process made a network connection
- Ties network traffic to a specific process — something standard firewall logs cannot do
- Focus on **which process** is connecting and **where** it's going
- Processes that should not make network connections doing so is a major red flag

---

*Lab environment: Windows Server 2022 – SOC Journey 2026*
