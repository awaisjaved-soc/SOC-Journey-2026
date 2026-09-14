# Event ID 5152 — Packet Dropped by WFP

**Log:** Security  
**Category:** Object Access  
**Subcategory:** Filtering Platform Packet Drop  
**Level:** Information  
**Lab Environment:** Windows Server 2022 — TECHCORP / techcorp.local  
**Lab Status:** ✅ Successfully Generated

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 5152 |
| Event Name | The Windows Filtering Platform has blocked a packet |
| Log Location | Windows Logs → Security |
| Audit Subcategory | Filtering Platform Packet Drop |
| Default State | Disabled — must be manually enabled |
| SACL Required | No |
| Volume | High — fires at packet level, lower than 5156 but higher than firewall rule events |

---

## What Is Event 5152?

Event 5152 fires when Windows Filtering Platform drops a packet at the filter layer — before the packet even reaches the point where named firewall rules are evaluated. While Event 5157 fires when a named Windows Firewall rule blocks a connection, 5152 fires at a lower level in the network stack, capturing drops that happen due to WFP built-in filters rather than administrator-created rules.

### 5152 vs 5157 — The Technical Difference

This is the most commonly confused pair in this category. The distinction comes down to **where in WFP the drop happens**:

```
Packet arrives
        ↓
WFP Layer 1 — Built-in WFP filters (low-level)
  If dropped here → Event 5152 fires
        ↓
WFP Layer 2 — Named firewall rules (Windows Firewall)
  If dropped here → Event 5157 fires
        ↓
Packet reaches application
```

In practice, when you create a named firewall block rule and a packet hits it, **both** 5152 and 5157 may fire — 5157 from the named rule match and 5152 from the underlying WFP filter. Event 5152 captures additional drops that 5157 misses — particularly malformed packets, connection state violations, and packets that fail protocol validation.

For SOC purposes, 5152 is most useful for detecting **port scanning**. When a scanner sends packets to hundreds of ports in rapid succession, most are dropped immediately by WFP before any named rule evaluation. Each dropped probe generates a 5152 event. A burst of 5152 events from different source ports targeting many destination ports on the same machine is a clear scan signature.

---

## Audit Policy Setup

```cmd
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
```

Verify:

```cmd
auditpol /get /subcategory:"Filtering Platform Packet Drop"
```

---

## Generating the Event

### Method 1 — Block Rule + Connection Attempt

```powershell
# Create a strict inbound block rule
New-NetFirewallRule `
    -DisplayName "SOC-Lab-Packet-Drop" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 8888 `
    -Action Block
Write-Host "Inbound block on port 8888 created." -ForegroundColor Yellow

# Attempt connection to the blocked port using loopback
# Loopback sends packet through WFP as inbound — it hits the block rule
Test-NetConnection -ComputerName 127.0.0.1 -Port 8888
# TcpTestSucceeded : False — packet was dropped, 5152 generated

# Cleanup
Remove-NetFirewallRule -DisplayName "SOC-Lab-Packet-Drop"
Write-Host "Rule removed." -ForegroundColor Green
```

### How Loopback Works Here

`127.0.0.1` is the loopback address — your machine talking to itself. When you run `Test-NetConnection -ComputerName 127.0.0.1 -Port 8888`, the packet leaves your network adapter, travels through the Windows network stack, and arrives back as an **inbound** packet. Because the direction is Inbound and the rule matches, WFP drops it. This is identical to what happens when an external machine tries to connect to a blocked port on your machine — just done locally without needing a second machine.

### Method 2 — GUI

1. Open `wf.msc` → **Inbound Rules** → **New Rule**
2. Port → TCP → Local Port: `8888` → Block → all profiles → name it `SOC-Lab-Drop`
3. Open PowerShell → run `Test-NetConnection -ComputerName 127.0.0.1 -Port 8888`
4. Event 5152 fires
5. Delete the rule after screenshot

---

## Detecting the Event

### GUI — Event Viewer

1. Event Viewer → Windows Logs → **Security**
2. Filter → Event ID: `5152` → OK
3. Look for entries near your test timestamp

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Application Name | Process that sent/received the dropped packet |
| Source Address | Where the packet came from |
| Source Port | Source port |
| Destination Address | Where it was going |
| Destination Port | Which port was targeted |
| Protocol | 6 = TCP / 17 = UDP |
| Filter Run-Time ID | Which WFP filter dropped it |
| Layer Name | Which WFP layer processed the drop |

### PowerShell Detection

```powershell
# Find packet drop events
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 5152
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue |
    Select-Object -First 10 |
    Select-Object TimeCreated, Message |
    Format-List
```

```powershell
# Scan detection — look for many drops to different ports from same source
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 5152
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time     = $_.TimeCreated
        SourceIP = ($data | Where-Object { $_.Name -eq 'SourceAddress' }).'#text'
        DestPort = ($data | Where-Object { $_.Name -eq 'DestPort'      }).'#text'
        Protocol = ($data | Where-Object { $_.Name -eq 'Protocol'      }).'#text'
    }
} | Group-Object SourceIP | Sort-Object Count -Descending | Format-Table Name, Count
```

---

## SOC Analyst Notes

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Occasional drops — normal network noise |
| 🟡 Medium | Repeated drops from same source to different ports |
| 🔴 High | Many drops in rapid succession — active port scan |
| 🔴 Critical | Drops from internal IP scanning internal network — lateral movement reconnaissance |

### MITRE ATT&CK Reference

- **T1046** — Network Service Discovery
- **T1595** — Active Scanning
