# Event 4624 – Successful Logon

## Event Description
Event 4624 is generated every time a user or system **successfully logs into** a Windows machine or server. It records critical details such as the username, logon type (interactive, network, RDP, etc.), source IP address, and time of login.

This is one of the **most frequently seen events** in a SOC environment and is heavily used during incident response to build timelines and detect unauthorized access.

### Logon Type Reference
| Logon Type | Description |
|------------|-------------|
| 2 | Interactive (local login) |
| 3 | Network (shared folder, etc.) |
| 10 | Remote Interactive (RDP) |
| 5 | Service logon |

---

## SOC Relevance
- First indicator that an attacker has **successfully gained access**
- Used to build **login timelines** during incident response
- Helps distinguish **normal user activity** from suspicious logons
- Correlate with **4625 (Failed Logon)** — multiple failures followed by a 4624 = successful brute force

---

## Lab Method 1 – Manual GUI

1. Lock the screen using `Win + L`
2. Log back in with correct username and password (use user `scott`)
3. Event 4624 will be generated on successful login

---

## Lab Method 2 – PowerShell

```powershell
# Confirm currently logged in user (triggers session activity)
whoami
```

> 💡 For a more realistic trigger: login as `scott`, perform some activity, then log off and check the event log.

---

## Detection Command

Run this on your **Domain Controller or target machine**:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 10 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time      = $_.TimeCreated
        User      = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        LogonType = ($xml.Event.EventData.Data | Where {$_.Name -eq 'LogonType'}).'#text'
        SourceIP  = ($xml.Event.EventData.Data | Where {$_.Name -eq 'IpAddress'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## What to Look For (SOC Analyst Tips)
- Logon **Type 10** (RDP) from unknown external IPs
- Successful logons **after multiple 4625 failures** (brute force success)
- Logons at **unusual hours** (e.g., 3 AM)
- Logons from **new or unexpected machines**
- `SYSTEM` or service account logons from interactive sessions

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Initial Access / Lateral Movement |
| Technique | T1078 – Valid Accounts |
