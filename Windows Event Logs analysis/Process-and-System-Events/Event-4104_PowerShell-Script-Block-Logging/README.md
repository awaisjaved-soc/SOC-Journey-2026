# Event 4104 – PowerShell Script Block Logging

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4104 |
| **Category** | Process & System Events |
| **Log** | Microsoft-Windows-PowerShell/Operational |
| **Tier** | 🔴 Tier 1 – Critical |
| **SOC Importance** | 🔴 Very High |

## What Is This Event?

Event 4104 records the **full content of PowerShell script blocks** as they are executed. This is one of the most powerful detection events available to SOC analysts because:

- Attackers **heavily rely on PowerShell** for everything — downloading payloads, lateral movement, credential dumping, and persistence
- Even if the command is **base64 encoded or obfuscated**, the actual decoded script content often appears in this event
- It captures the real intent of the command, not just the process name

Without 4104, you might see `powershell.exe` launched in Event 4688 but have no idea what it actually ran. With 4104, you see the full script.

---

## Setup – Must Do First

Run these commands as **Administrator**:

```powershell
# Enable Script Block Logging via Registry
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

gpupdate /force
```

### Verify the Setting is Applied

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
```

Expected output: `EnableScriptBlockLogging : 1`

> **Note:** After enabling, open a **new PowerShell window** before testing. The setting does not apply to already-open PowerShell sessions.

---

## How to Generate This Event

### Method 1 – Simple Script Block
```powershell
Write-Host "This is a test for Event 4104"
Get-Process | Select-Object -First 3
```

---

<img width="470" height="330" alt="Screenshot_1" src="https://github.com/user-attachments/assets/7b6e439c-918b-4a3d-9ff1-7ca4c7a311d9" />

---

<img width="624" height="431" alt="Screenshot_2" src="https://github.com/user-attachments/assets/9ced8c0b-d7d1-42d1-8ac0-f997ed399a25" />

---

### Method 2 – Encoded Command (Simulates Attacker Obfuscation)
```powershell
# This is base64 encoded "get-process"
powershell -enc ZwBlAHQALQBwAHIAbwBjAGUAcwBzAA==
```

> Even though the command is encoded, Event 4104 will log the **decoded content** — this is exactly why attackers hate script block logging and why SOC analysts love it.

### Method 3 – Multi-line Script
```powershell
$a = "Hello"
$b = "SOC"
Write-Host "$a $b - Event 4104 Test"
Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 5
```

---

## Detection Commands

### Basic Detection
```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104]]" -MaxEvents 5 |
ForEach-Object {
    [PSCustomObject]@{
        Time    = $_.TimeCreated
        Message = $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length))
    }
} | Format-List
```
---

<img width="675" height="386" alt="detection" src="https://github.com/user-attachments/assets/83063b73-9f76-46b5-a85c-f4d4b726d70b" />

---


<img width="672" height="384" alt="allowing" src="https://github.com/user-attachments/assets/78065f80-82c0-4e0b-ba45-8a64c9e52059" />


---

### See Full Script Content
```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104]]" -MaxEvents 3 |
Select-Object TimeCreated, Message | Format-List
```

---

## SOC Analyst Notes

### Why This Event Is So Valuable

| Attacker Technique | What 4104 Reveals |
|-------------------|-------------------|
| Base64 encoded commands | The **decoded** actual command |
| Obfuscated scripts | The underlying logic |
| Downloaded payloads (IEX) | The full downloaded script content |
| Credential dumping commands | The exact Mimikatz or dump command used |
| Reverse shells | The IP address and port of the C2 server |

### Dangerous Keywords to Search For in 4104 Events

```powershell
# Search for suspicious keywords in recent 4104 events
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104]]" -MaxEvents 50 |
Where-Object {
    $_.Message -match "IEX|Invoke-Expression|DownloadString|WebClient|mimikatz|Bypass|encodedcommand|FromBase64"
} | Select-Object TimeCreated, Message | Format-List
```

| Keyword | What It Suggests |
|---------|-----------------|
| `IEX` / `Invoke-Expression` | Executing downloaded code |
| `DownloadString` / `WebClient` | Downloading payload from internet |
| `mimikatz` | Credential dumping tool |
| `-Bypass` | Bypassing execution policy |
| `FromBase64String` | Decoding encoded payload |
| `Invoke-Mimikatz` | In-memory credential dumping |
| `Net.WebClient` | HTTP download in PowerShell |

### Event Log Location

This event is in the **PowerShell Operational log**, not the Security log:

```
Event Viewer → Applications and Services Logs
    → Microsoft
        → Windows
            → PowerShell
                → Operational
```

Or via PowerShell:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Id -eq 4104}
```
