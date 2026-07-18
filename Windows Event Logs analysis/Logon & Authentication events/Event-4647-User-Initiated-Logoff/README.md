# Event 4647 – User Initiated Logoff

## Event Description
Event 4647 is generated when a **user manually initiates a logoff** by clicking Sign Out from the Start menu or using `shutdown /l`. It is very similar to Event 4634 but specifically records a **user-initiated** action rather than a system or session timeout.

> 💡 Key difference: **4634** = session ended (any reason) | **4647** = user clicked "Sign out" themselves

---

## SOC Relevance
- Helps **differentiate** between normal user logoff vs system-forced termination
- Useful for understanding **user behavior patterns**
- Can indicate an attacker **cleanly logging off** after completing their objective
- Pairs with 4624 to complete full session timeline

---

## Lab Method 1 – Manual GUI

1. Login as `scott`
2. Click **Start** → **Power button** → **Sign out**
3. Event 4647 will be generated

---

## Lab Method 2 – PowerShell

```powershell
shutdown /l
```

---

## Detection Command

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4647} -MaxEvents 5 |
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
- 4647 appearing for **admin accounts at odd hours** (attacker signing out after work)
- 4647 without a corresponding **4624** earlier (session anomaly)
- Multiple sign-outs in quick succession across different accounts
- Sign-out on **critical servers** (Domain Controller, file servers) unexpectedly

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Technique | T1070 – Indicator Removal (cleaning up session traces) |
