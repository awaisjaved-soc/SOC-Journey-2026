# Event ID 5154 — Application Listening on Port

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
| Event ID | 5154 |
| Event Name | The Windows Filtering Platform has permitted an application to listen on a port |
| Log Location | Windows Logs → Security |
| Audit Subcategory | Filtering Platform Connection |
| Default State | Disabled — must be manually enabled |
| SACL Required | No |
| Volume | Low-Medium — only fires when a process opens a listening socket |

---

## What Is Event 5154?

Event 5154 fires when an application opens a TCP or UDP socket and starts listening for incoming connections. This is fundamentally different from 5156 and 5157 which track active connections — 5154 tracks the moment a process announces itself as available to receive connections.

Think of it as the difference between a phone call (active connection) and listing your phone number in a directory (listening on a port). Event 5154 is the directory listing — it says "this process is now reachable at this address."

### Why This Is a Backdoor Detection Event

Legitimate services that listen on ports are well-known and consistent. Web servers listen on 80 and 443. RDP listens on 3389. SMB listens on 445. DNS listens on 53. These processes and port combinations are predictable, documented, and expected.

When an unknown process starts listening on an unusual port — especially a high ephemeral port like 4444, 8080, 9999, or any port above 49000 that is not associated with a known service — that is a strong indicator of a backdoor being established. Attackers who compromise a machine and set up a listener for incoming connections from their C2 infrastructure generate Event 5154. The process name and port combination is immediately suspicious when it does not match known-good baselines.

### 5154 vs 5158 — Understanding the Pair

These two events almost always fire together for the same action:

- **5154** fires when WFP **permits the listen** — the application's listen request was approved
- **5158** fires when WFP **permits the bind** — the underlying socket bind to the port was approved

In practice, opening a listener generates both. 5154 is the higher-level event that SOC analysts focus on because it contains the more useful information in readable format.

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

### Method 1 — PowerShell TCP Listener (Best Lab Method)

```powershell
# Start a TCP listener — simulates a backdoor opening a port
$listener = [System.Net.Sockets.TcpListener]::new(
    [System.Net.IPAddress]::Any, 7777
)
$listener.Start()
Write-Host "Listener started on port 7777 — Event 5154 generated." -ForegroundColor Yellow
Write-Host "Source Address: 0.0.0.0 (all interfaces)" -ForegroundColor Cyan
Write-Host "Source Port: 7777" -ForegroundColor Cyan
Write-Host "Check Security log for Event 5154 now." -ForegroundColor Green

# Keep running for screenshot, then stop
Start-Sleep -Seconds 5
$listener.Stop()
Write-Host "Listener stopped." -ForegroundColor Green
```

> **Port Already in Use Error?** If you see `Only one usage of each socket address` it means a previous listener session is still holding the port. Use a different port number:
> ```powershell
> $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, 6666)
> ```

### Method 2 — Start a Listener and Connect to It

This generates 5154 (listen), 5158 (bind), and 5156 (connection allowed) all together:

```powershell
# WINDOW 1 — Start listener
$listener = [System.Net.Sockets.TcpListener]::new(
    [System.Net.IPAddress]::Any, 7777
)
$listener.Start()
Write-Host "Listener active on port 7777." -ForegroundColor Green

# WINDOW 2 — Connect to it
Test-NetConnection -ComputerName 127.0.0.1 -Port 7777
# TcpTestSucceeded : True

# Stop listener in Window 1 after screenshot
$listener.Stop()
```

### Method 3 — GUI (netsh)

```cmd
:: Start a simple listener using netsh
netsh http add urlacl url=http://+:8080/ user=Everyone
```

---

## Detecting the Event

### GUI — Event Viewer

1. Event Viewer → Windows Logs → **Security**
2. Filter → Event ID: `5154` → OK
3. Look for entries from your PowerShell session

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Application Name | Which process opened the listener — powershell.exe on unusual port is suspicious |
| Source Address | `0.0.0.0` = listening on all interfaces (most exposed) / specific IP = bound to one interface |
| Source Port | Which port is being listened on — high/unusual ports are suspicious |
| Protocol | 6 = TCP / 17 = UDP |

### PowerShell Detection

```powershell
# Find all listener events in last hour
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 5154
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        Application = ($data | Where-Object { $_.Name -eq 'Application'  }).'#text'
        SourceIP    = ($data | Where-Object { $_.Name -eq 'SourceAddress' }).'#text'
        SourcePort  = ($data | Where-Object { $_.Name -eq 'SourcePort'   }).'#text'
        Protocol    = ($data | Where-Object { $_.Name -eq 'Protocol'     }).'#text'
    }
} | Format-Table -AutoSize
```

```powershell
# Hunt for unusual listeners — exclude known-good ports
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 5154
    StartTime = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue | Where-Object {
    $msg = $_.Message
    $msg -notlike "*:80 *"   -and
    $msg -notlike "*:443 *"  -and
    $msg -notlike "*:3389*"  -and
    $msg -notlike "*:445*"   -and
    $msg -notlike "*:53 *"   -and
    $msg -notlike "*:135*"
} | ForEach-Object {
    Write-Host "=== UNUSUAL LISTENER DETECTED ===" -ForegroundColor Red
    Write-Host "Time    : $($_.TimeCreated)"
    Write-Host "Details : $($_.Message)"
    Write-Host ""
}
```

```powershell
# Find your specific lab listener
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = @(5154, 5158)
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -like "*powershell*" -or
    $_.Message -like "*7777*"       -or
    $_.Message -like "*6666*"
} | Select-Object TimeCreated, Id, Message | Format-List
```

---

## SOC Analyst Notes

### Known-Good Listeners vs Suspicious Listeners

| Process + Port | Verdict |
|---|---|
| `svchost.exe:445` | Normal — SMB file sharing |
| `svchost.exe:3389` | Normal — Remote Desktop |
| `dns.exe:53` | Normal — DNS server |
| `System:135` | Normal — RPC endpoint mapper |
| `powershell.exe:7777` | **Investigate — unusual listener** |
| `cmd.exe` + any port | **Critical — shell listener** |
| Unknown process + high port | **Critical — possible backdoor** |

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Known system process, well-known port, expected service |
| 🟡 Medium | Admin tool (netcat, python) on unusual port during maintenance |
| 🔴 High | PowerShell or script engine listening on non-standard port |
| 🔴 Critical | Unknown process listening on any port — investigate immediately |

### MITRE ATT&CK Reference

- **T1571** — Non-Standard Port
- **T1095** — Non-Application Layer Protocol
- **T1090.001** — Proxy: Internal Proxy (listener used as relay)
