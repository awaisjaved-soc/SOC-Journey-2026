# Event 4625 – Failed Logon

## Event Description
Event 4625 is generated whenever a **logon attempt fails** due to wrong username, wrong password, or other authentication issues. It contains critical details like the attempted username, source IP, and the reason for failure.

This is one of the **most important events for detecting attacks** like brute force, password spraying, and credential stuffing.

### Common Failure Reason Codes
| Sub Status Code | Meaning |
|-----------------|---------|
| 0xC000006A | Wrong password |
| 0xC0000064 | Username does not exist |
| 0xC0000234 | Account locked out |
| 0xC000006F | Logon outside allowed hours |

---

## SOC Relevance
- Primary indicator of **brute force attacks**
- Multiple 4625s in short time = **password spraying**
- 4625 followed by 4624 = **successful brute force** — critical alert
- Helps identify **targeted accounts** under attack

---

## Lab Method 1 – Manual GUI

1. Go to the login screen of your Windows Server / client
2. Try logging in as `scott` with a **wrong password** multiple times (5-6 times)
3. Each failed attempt generates Event 4625

---

## Lab Method 2 – PowerShell

```powershell
$username = "scott"
$wrongpass = ConvertTo-SecureString "WrongPass123" -AsPlainText -Force

1..6 | ForEach-Object {
    $cred = New-Object System.Management.Automation.PSCredential($username, $wrongpass)
    Start-Process powershell.exe -Credential $cred -NoNewWindow -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 700
}
```

---

## Detection Command

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time     = $_.TimeCreated
        User     = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        SourceIP = ($xml.Event.EventData.Data | Where {$_.Name -eq 'IpAddress'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## What to Look For (SOC Analyst Tips)
- **5+ failures in under 1 minute** from same IP = brute force
- Same IP targeting **multiple different usernames** = password spraying
- Failures against **admin or service accounts**
- Failures from **external/unknown IPs**
- 4625 immediately followed by 4624 for same user = **attacker succeeded**

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Technique | T1110 – Brute Force |
