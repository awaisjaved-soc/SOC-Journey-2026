# Event 4634 – Logoff

## Event Description
Event 4634 is generated when a **user session ends** — either by logging off, session timeout, or system-initiated termination. It records the username and logon ID to link back to the original 4624 logon event.

This event **pairs with Event 4624** to give a complete picture of how long a user was logged in.

---

## SOC Relevance
- Helps calculate **session duration** (4624 login time → 4634 logoff time)
- Detect **suspiciously short sessions** (attacker grabbed what they needed and left fast)
- Detect **sessions that never ended** (persistent access)
- Important for **building user activity timelines** during incident response

---

## Lab Method 1 – Manual GUI

1. Login as `scott`
2. Do some activity for a few minutes
3. Press `Ctrl + Alt + Del` → Click **Sign out**
4. Event 4634 will be generated on logoff

---

## Lab Method 2 – PowerShell

```powershell
logoff
```

---

## Detection Command

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4634} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time = $_.TimeCreated
        User = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## What to Look For (SOC Analyst Tips)
- Sessions with **very short duration** (login and logoff within seconds)
- Accounts that logged in but **4634 never appeared** (session still active — persistent access?)
- Logoff events from **service or system accounts** at unusual times
- Correlate the **LogonID** in 4634 with the same field in 4624 to match sessions

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Technique | T1078 – Valid Accounts (session tracking) |
