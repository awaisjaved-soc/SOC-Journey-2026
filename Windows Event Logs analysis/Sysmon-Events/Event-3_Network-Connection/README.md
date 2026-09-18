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


<img width="469" height="328" alt="Screenshot_3" src="https://github.com/user-attachments/assets/c444e430-5be4-4a26-8674-0bb98a8b4f23" />

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
   
---

<img width="547" height="193" alt="Screenshot_2" src="https://github.com/user-attachments/assets/21615b32-b3fb-471b-bb6e-6c6826817944" />

---


<img width="483" height="341" alt="Screenshot_7" src="https://github.com/user-attachments/assets/29170fc9-fcf5-4ddb-90bc-1a63e546d34a" />

---


### Method 2: PowerShell (Recommended)

```powershell
# Generate network connection events
Test-NetConnection -ComputerName google.com -Port 443
Test-NetConnection -ComputerName 8.8.8.8 -Port 53
Invoke-WebRequest -Uri "https://www.example.com" -UseBasicParsing
```

---

<img width="931" height="360" alt="Screenshot_12" src="https://github.com/user-attachments/assets/171662b1-b936-4fe9-a167-0c826db33123" />


---

<img width="832" height="311" alt="Screenshot_1" src="https://github.com/user-attachments/assets/b88c31e7-5478-4f08-8dfc-91da84d74d14" />


---




## Detection Commands

### Basic View

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=3]]" -MaxEvents 10 |
Select-Object TimeCreated, Id, Message | Format-List
```
---

<img width="469" height="328" alt="Screenshot_3" src="https://github.com/user-attachments/assets/0679c0b4-1174-4c19-9699-04c8f05b013d" />

---


<img width="468" height="332" alt="Screenshot_4" src="https://github.com/user-attachments/assets/3cbec8fd-0656-450c-99ef-6baead228bda" />

---

<img width="468" height="330" alt="Screenshot_5" src="https://github.com/user-attachments/assets/0eeabc26-e6be-40ef-8670-6cb108b47c1d" />

---


<img width="470" height="331" alt="Screenshot_8" src="https://github.com/user-attachments/assets/bec9ab27-6c33-427a-94da-754c9c4c4092" />

---


<img width="615" height="102" alt="Screenshot_6" src="https://github.com/user-attachments/assets/181cbe3f-bbaf-4821-ae55-ba6a3d09115a" />

---

<img width="469" height="330" alt="Screenshot_9" src="https://github.com/user-attachments/assets/d65ee00c-ee9b-4221-b341-e172350e9ce3" />

---


<img width="466" height="328" alt="Screenshot_13" src="https://github.com/user-attachments/assets/5094fc6c-59a9-4855-b142-d8fd49714222" />

---


<img width="468" height="331" alt="Screenshot_14" src="https://github.com/user-attachments/assets/bb62754b-363b-44c7-bf04-ced1071f3c16" />

---


<img width="471" height="331" alt="Screenshot_15" src="https://github.com/user-attachments/assets/0cc1b877-29ee-4e45-a9f5-ec38dc9f0bc7" />

---

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

<img width="955" height="350" alt="Screenshot_18" src="https://github.com/user-attachments/assets/e4636272-f832-4ae9-bb7f-f5dff86da9ec" />

---
<img width="633" height="268" alt="Screenshot_17" src="https://github.com/user-attachments/assets/af4223b6-4730-41a9-952b-7494bfce83e6" />

---

<img width="868" height="312" alt="Screenshot_16" src="https://github.com/user-attachments/assets/b2af5a60-4079-496c-9829-07f279435034" />

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
