# Event 4743 – Computer Account Deleted

## Event Description
This event is logged when a **computer account is deleted** from the Active Directory domain.  
Legitimate deletions happen during decommissioning of machines, but attackers also delete accounts to **cover their tracks** after use.

## SOC Relevance
After using a rogue computer account for lateral movement or Kerberos attacks, an attacker may delete it to remove evidence. Sudden deletion of computer accounts — especially ones recently created — is a strong red flag.

---

## Lab Method 1 – Manual GUI

1. Open **Active Directory Users and Computers** (`dsa.msc`)
2. Navigate to the **Computers** container
3. Right-click the computer account → **Delete**
4. Confirm deletion

---

## Lab Method 2 – PowerShell

```powershell
Remove-ADComputer -Identity "ROGUE-PC-01" -Confirm:$false
```

---

## Detection Command

Run this on your **Domain Controller** to detect Event 4743:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4743} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time         = $_.TimeCreated
        DeletedBy    = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
        ComputerName = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## What to Look For (SOC Analyst Tips)
- Computer account deleted **shortly after it was created** (Event 4741 → 4743 pair)
- Deletion performed by a **non-standard admin** account
- Deletion of accounts that had **recent logon activity**
- Multiple deletions in a short time window (cleanup sweep)

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Technique | T1070 – Indicator Removal |
