# Event ID 5158 — Port Bind Allowed

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
| Event ID | 5158 |
| Event Name | The Windows Filtering Platform has permitted a bind to a local port |
| Log Location | Windows Logs → Security |
| Audit Subcategory | Filtering Platform Connection |
| Default State | Disabled — must be manually enabled |
| SACL Required | No |
| Volume | High — fires for every socket bind including system processes |

---

<img width="471" height="328" alt="Screenshot_1" src="https://github.com/user-attachments/assets/2b74ca36-af82-4492-8021-294344d2115c" />

---


## What Is Event 5158?

Event 5158 fires when Windows Filtering Platform permits a process to bind to a local port. A socket bind is the low-level network operation that claims a specific port on a specific network interface for a process — it is the foundation that all network listeners and outbound connections are built on.

Before any process can listen for incoming connections or establish outbound connections, it must first bind a socket to a local port. Event 5158 captures this binding moment at the WFP layer.

### 5158 vs 5154 — The Technical Distinction

These two events are closely related and often fire together, but they capture different layers of the same action:

| | 5154 | 5158 |
|---|---|---|
| What it captures | Application permitted to listen | Socket bind to port permitted |
| Level | Higher — application layer | Lower — socket/WFP layer |
| When it fires | When listen() system call succeeds | When bind() system call succeeds |
| Fires for outbound? | No — only for listeners | Yes — also for outbound connections |
| Primary SOC use | Backdoor listener detection | Port monitoring, bind audit |

The key difference is that 5158 fires for **both** listener sockets AND client sockets. When `powershell.exe` makes an outbound connection, it also binds to a local ephemeral port first — this bind generates 5158. Event 5154 only fires for actual listening sockets.

### Lab Observation — High Volume from lsass.exe

When you ran the detection command, you saw hundreds of 5158 events from `lsass.exe` with various high port numbers. This is completely normal on a Domain Controller. `lsass.exe` handles all Kerberos authentication and creates a new socket for each authentication operation. Each socket bind generates a 5158 event. This background noise is why filtering by process name or specific port is essential when using 5158 for detection.

---

## Audit Policy Setup

```cmd
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

---

## Generating the Event

The same listener command used for Event 5154 also generates 5158 — they fire together as a pair:

### PowerShell Method

```powershell
# Start listener — generates both 5154 and 5158
$listener = [System.Net.Sockets.TcpListener]::new(
    [System.Net.IPAddress]::Any, 7777
)
$listener.Start()
Write-Host "Port 7777 bound — Events 5154 and 5158 both fired." -ForegroundColor Yellow
Write-Host "Check Security log for 5158 — look for port 7777 from powershell.exe" -ForegroundColor Cyan

Start-Sleep -Seconds 5
$listener.Stop()
Write-Host "Listener stopped." -ForegroundColor Green
```

---


## Detecting the Event

### GUI — Event Viewer

1. Event Viewer → Windows Logs → **Security**
2. Filter → Event ID: `5158` → OK
3. You will see many entries — filter by port number to find your lab event

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Application Name | Which process bound the port |
| Source Address | `0.0.0.0` = all IPv4 interfaces / `::` = all IPv6 interfaces |
| Source Port | The port that was bound — your lab port will be here |
| Protocol | 6 = TCP / 17 = UDP |
| Layer Name | `Resource Assignment` = normal bind layer |

---

<img width="471" height="328" alt="Screenshot_1" src="https://github.com/user-attachments/assets/b2e15d13-30a0-4516-b266-a7dc28bdd3c1" />

---

<img width="469" height="330" alt="Screenshot_2" src="https://github.com/user-attachments/assets/1f6182f3-e317-442e-a36c-cccbd2fef5ac" />

---

<img width="619" height="252" alt="Screenshot_3" src="https://github.com/user-attachments/assets/6231802d-94de-4ffb-9adc-93162836c350" />

---

<img width="469" height="330" alt="Screenshot_10" src="https://github.com/user-attachments/assets/ebf2351c-8512-473d-80f4-cd056b471105" />

---


### PowerShell Detection

```powershell
# Find your specific lab port bind — filter by port number
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 5158
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -like "*7777*" -or
    $_.Message -like "*6666*" -or
    $_.Message -like "*powershell*"
} | Select-Object TimeCreated, Message | Format-List
```
---

<img width="906" height="398" alt="Screenshot_4" src="https://github.com/user-attachments/assets/74bfa86e-ebf1-4b83-90dc-0dc78233d5b9" />

---


```powershell
# Find both 5154 and 5158 together — confirm they fired as a pair
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = @(5154, 5158)
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -like "*powershell*" -or $_.Message -like "*7777*"
} | Select-Object TimeCreated, Id, Message | Format-List
```
---

<img width="930" height="413" alt="Screenshot_5" src="https://github.com/user-attachments/assets/297b960a-1e12-418c-94aa-66f15ffafffa" />

---


```powershell
# Exclude lsass and svchost noise — show only unexpected binds
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 5158
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -notlike "*lsass*"   -and
    $_.Message -notlike "*svchost*" -and
    $_.Message -notlike "*System*"
} | ForEach-Object {
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

---

<img width="877" height="230" alt="Screenshot_6" src="https://github.com/user-attachments/assets/aa030035-85c8-4671-a013-daf694bcbadd" />

---

<img width="952" height="416" alt="sdadasda" src="https://github.com/user-attachments/assets/c4c6e838-77af-42ec-9e9f-216660e26518" />

---
## SOC Analyst Notes

### Handling the Volume Problem

5158 is extremely high volume, especially on Domain Controllers. The practical approach is to never alert on raw 5158 events — instead use it for:

1. **Correlation with 5154** — when 5154 fires for an unusual listener, check the matching 5158 to confirm the port bind details
2. **Investigation support** — after identifying a suspicious process via 4688, check 5158 to see what ports it bound to
3. **Baseline comparison** — build a list of expected processes and their normal port ranges, then alert on deviations

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | `lsass.exe`, `svchost.exe`, `System` — normal DC activity |
| 🟡 Medium | Admin tool binding to unusual port during maintenance window |
| 🔴 High | `powershell.exe` or `cmd.exe` binding to non-ephemeral port |
| 🔴 Critical | Unknown executable binding to any port |

### MITRE ATT&CK Reference

- **T1571** — Non-Standard Port
- **T1095** — Non-Application Layer Protocol
