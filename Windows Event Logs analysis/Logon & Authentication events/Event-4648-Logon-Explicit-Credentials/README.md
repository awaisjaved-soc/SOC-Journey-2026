# Event 4648 – Logon with Explicit Credentials

## Event Description
Event 4648 is generated when a user or process **uses alternate credentials** to run something — for example, using the `runas` command or right-clicking "Run as different user." It records both the **account that initiated the action** and the **target account** being used.

This event is critical because it shows someone is **using credentials other than their own** — which is a common attacker technique.

---

## SOC Relevance
- Key indicator of **lateral movement** — attacker using stolen credentials on another machine
- Detects **Pass-the-Hash (PtH)** and **Pass-the-Ticket** attacks
- Shows **privilege escalation attempts** via runas
- Helps identify **credential theft** in progress

---

## Lab Method 1 – Manual GUI

1. Hold **Shift** and **Right-click** on Command Prompt or any application
2. Click **"Run as different user"**
3. Enter `scott`'s credentials
4. Event 4648 will be generated

---

## Lab Method 2 – PowerShell

```powershell
Start-Process powershell.exe -Credential (Get-Credential) -ArgumentList "-NoExit"
```

> A credential popup will appear — enter `scott`'s username and password to trigger the event.

---

## Detection Command

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4648} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time         = $_.TimeCreated
        TargetUser   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        UsingAccount = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## What to Look For (SOC Analyst Tips)
- **Non-admin users** using explicit credentials to run processes as admin
- 4648 seen on **multiple machines** for the same account = lateral movement
- `SubjectUserName` and `TargetUserName` are **completely different accounts** = suspicious
- 4648 combined with **4624 Type 3 (network logon)** = strong lateral movement indicator
- Appearing on **servers or Domain Controllers** from workstation accounts

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Lateral Movement / Privilege Escalation |
| Technique | T1550.002 – Pass the Hash / T1078 – Valid Accounts |
