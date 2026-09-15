# Event ID 5157 — Network Connection Blocked

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
| Event ID | 5157 |
| Event Name | The Windows Filtering Platform has blocked a connection |
| Log Location | Windows Logs → Security |
| Audit Subcategory | Filtering Platform Connection |
| Default State | Disabled — must be manually enabled |
| SACL Required | No |
| Volume | Medium — only fires when firewall blocks a connection |

---

<img width="467" height="332" alt="Screenshot_1" src="https://github.com/user-attachments/assets/28bf88b0-574f-4f7f-87e5-978853863b18" />

---


## What Is Event 5157?

Event 5157 fires when Windows Filtering Platform blocks a network connection because a firewall rule matched and the action was Block. Unlike Event 5156 which fires for every allowed connection (generating massive volume), 5157 only fires when something is actually stopped — making it lower volume and inherently higher signal value.

Every 5157 event represents a connection attempt that failed because Windows Firewall prevented it. In SOC work this is interesting for two opposite reasons.

**Detecting failed C2 attempts** — When malware on a compromised machine tries to reach its command server but the firewall is blocking outbound connections to that destination, 5157 fires. The malware is present and active but the network controls are working. The combination of a 5157 showing repeated blocked outbound attempts from an unusual process tells you that something is trying to communicate out but failing. This is containment working — but it still means you have an infection to investigate.

**Detecting reconnaissance** — An attacker who has compromised a machine and is scanning internal network ports generates streams of 5157 events. If port 22, 23, 80, 443, 3389 are all blocked and the attacker scans them sequentially, each blocked probe appears as a separate 5157 event. The pattern — one process, many blocked destinations in rapid succession — is a clear scan signature.

---

## How the Block Works

When a connection attempt is made, the packet journey ends like this:

```
Process attempts outbound TCP connection
        ↓
Packet enters Windows network stack
        ↓
WFP intercepts the packet
        ↓
WFP evaluates rules:
  Protocol matches → ✅
  Direction matches → ✅
  Port matches → ✅
  Action = BLOCK
        ↓
Packet is dropped — never leaves the machine
        ↓
Event 5157 fires — connection blocked recorded
        ↓
Calling process receives connection refused/timeout error
```

The process gets an error. The packet never reaches the destination. The Security log has a complete record of the attempt.

---

## Audit Policy Setup

```cmd
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

Verify:

```cmd
auditpol /get /subcategory:"Filtering Platform Connection"
```

---


## Generating the Event

### Method 1 — PowerShell with Temporary Block Rule (Recommended)

```powershell
# Step 1: Create a block rule for outbound port 80
New-NetFirewallRule `
    -DisplayName "SOC-Lab-Block-Test" `
    -Direction Outbound `
    -Protocol TCP `
    -RemotePort 80 `
    -Action Block
Write-Host "Block rule created — outbound port 80 now blocked." -ForegroundColor Yellow

# Step 2: Attempt the blocked connection
try {
    Invoke-WebRequest -Uri "http://www.google.com" -UseBasicParsing -TimeoutSec 5
} catch {
    Write-Host "Connection blocked as expected — Event 5157 generated." -ForegroundColor Red
}

# Step 3: Remove the rule
Remove-NetFirewallRule -DisplayName "SOC-Lab-Block-Test"
Write-Host "Block rule removed." -ForegroundColor Green
```

---

<img width="918" height="427" alt="Screenshot_11" src="https://github.com/user-attachments/assets/b457196f-d062-4f11-87db-9001f27da0b4" />

---


### Method 2 — Block Inbound and Test with Loopback

```powershell
# Create inbound block rule
New-NetFirewallRule `
    -DisplayName "SOC-Lab-Packet-Drop" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 8888 `
    -Action Block
Write-Host "Inbound block on port 8888 created." -ForegroundColor Yellow

# Attempt connection — loopback sends packet as inbound which hits the block rule
Test-NetConnection -ComputerName 127.0.0.1 -Port 8888
# TcpTestSucceeded : False confirms the block worked

# Cleanup
Remove-NetFirewallRule -DisplayName "SOC-Lab-Packet-Drop"
Write-Host "Rule removed." -ForegroundColor Green
```

### Method 3 — GUI

1. Open `wf.msc` → **Outbound Rules** → **New Rule**
2. Rule type: **Port** → TCP → specific port: `80`
3. Action: **Block the connection** → apply to all profiles
4. Name it `SOC-Lab-Block`
5. Try to browse any HTTP site → Event 5157 fires
6. Delete the rule after screenshot

---

<img width="955" height="384" alt="Screenshot_12" src="https://github.com/user-attachments/assets/1d7373a0-11fe-4435-bd08-c14bb0e0df03" />

---

## Detecting the Event

### GUI — Event Viewer

1. Event Viewer → Windows Logs → **Security**
2. Filter → Event ID: `5157` → OK
3. Find entries timestamped when you ran the block test

---

<img width="467" height="332" alt="Screenshot_1" src="https://github.com/user-attachments/assets/39cdac9f-ff11-48f6-b14a-bf640ead1d22" />

---

<img width="468" height="332" alt="Screenshot_2" src="https://github.com/user-attachments/assets/fd52669d-27bc-48fa-bfc4-006d9e69188a" />

---

<img width="471" height="330" alt="Screenshot_3" src="https://github.com/user-attachments/assets/4826ed63-76b0-44ab-a0be-16be6012a71d" />

---

<img width="466" height="329" alt="Screenshot_4" src="https://github.com/user-attachments/assets/8e42ce19-e654-437e-bcc6-bb41da45da1e" />

---

<img width="471" height="332" alt="Screenshot_5" src="https://github.com/user-attachments/assets/c32d04c7-8f12-4825-8abb-788f8162e706" />

---

<img width="472" height="330" alt="Screenshot_6" src="https://github.com/user-attachments/assets/c131fbdf-2a9b-480f-9647-c1668644e5cb" />

---


**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Application Name | What process was blocked — unexpected processes are most interesting |
| Direction | Outbound blocked = process tried to communicate out |
| Source Address | Your machine IP |
| Destination Address | Where it was trying to go |
| Destination Port | Which port was blocked |
| Filter Run-Time ID | Which firewall rule caused the block |
| Protocol | 6 = TCP / 17 = UDP |

---

<img width="468" height="332" alt="Screenshot_7" src="https://github.com/user-attachments/assets/2c968dbf-892e-4d0b-8e5d-5f9dcd75440a" />

---

<img width="470" height="333" alt="Screenshot_8" src="https://github.com/user-attachments/assets/a16f0115-fab7-4f49-bc82-e33b43e9efbd" />

---

<img width="475" height="334" alt="Screenshot_9" src="https://github.com/user-attachments/assets/1ad277ec-9c36-401a-9b5a-8796ebb41c44" />

---

<img width="632" height="260" alt="Screenshot_17" src="https://github.com/user-attachments/assets/2763e61f-d98d-496a-b68c-e5948b54d1db" />

---

### PowerShell Detection

```powershell
# Recent blocked connections
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 5157
    StartTime = (Get-Date).AddHours(-1)
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        Application = ($data | Where-Object { $_.Name -eq 'Application'   }).'#text'
        Direction   = ($data | Where-Object { $_.Name -eq 'Direction'     }).'#text'
        SourceIP    = ($data | Where-Object { $_.Name -eq 'SourceAddress' }).'#text'
        DestIP      = ($data | Where-Object { $_.Name -eq 'DestAddress'   }).'#text'
        DestPort    = ($data | Where-Object { $_.Name -eq 'DestPort'      }).'#text'
        Protocol    = ($data | Where-Object { $_.Name -eq 'Protocol'      }).'#text'
    }
} | Format-Table -AutoSize
```
---

<img width="913" height="473" alt="Screenshot_10" src="https://github.com/user-attachments/assets/6389d2cd-e6b3-403b-8c1b-f628a2cbe5d1" />

---


```powershell
# Detect scanning pattern — many blocked connections from same process
$blocked = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 5157
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue

Write-Host "Total blocked connections in last hour: $($blocked.Count)"

if ($blocked.Count -gt 20) {
    Write-Host "WARNING: High block count — possible C2 beacon or port scan" -ForegroundColor Red
}

# Group by process to find the most active blocked process
$blocked | ForEach-Object {
    $xml = [xml]$_.ToXml()
    ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Application' }).'#text'
} | Group-Object | Sort-Object Count -Descending | Select-Object -First 5 | Format-Table Name, Count
```

---

<img width="709" height="262" alt="Screenshot_18" src="https://github.com/user-attachments/assets/faa8872b-be03-4879-ad71-5e73bc5624d8" />

---


## SOC Analyst Notes

### 5157 vs 5156 — The Key Difference

| | 5156 | 5157 |
|---|---|---|
| What it means | Connection was allowed | Connection was blocked |
| Volume | Very high | Medium |
| Signal value | Low without filtering | Higher — something was stopped |
| Primary use | Investigation after incident | Real-time alerting on patterns |

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Browser blocked on a restricted port — expected behaviour |
| 🟡 Medium | Unknown process blocked trying to reach external IP |
| 🔴 High | Many rapid blocks from same process — possible scan or C2 beacon |
| 🔴 Critical | Known malware process blocked trying to reach known C2 IP |

### MITRE ATT&CK Reference

- **T1071** — Application Layer Protocol
- **T1110** — Brute Force (blocked connection floods)
- **T1046** — Network Service Discovery (port scanning generates blocked connections)
