# Event 4741 – Computer Account Created

## Event Description
This event is logged when a **new computer account** is added to the Active Directory domain.  
Every machine that joins the domain gets a computer account — but attackers can also create **rogue computer accounts** for malicious purposes.

## SOC Relevance
Attackers create rogue computer accounts to enable **lateral movement**, **persistence**, or to abuse Kerberos (e.g., Resource-Based Constrained Delegation attacks like MachineAccountQuota abuse).

---

## Lab Method 1 – Manual GUI

1. Open **Active Directory Users and Computers** (`dsa.msc`)
2. Navigate to the **Computers** container (or any OU)
3. Right-click → **New** → **Computer**
4. Enter a computer name (e.g., `ROGUE-PC-01`)
5. Click **OK**

---

## Lab Method 2 – PowerShell

```powershell
New-ADComputer -Name "ROGUE-PC-01" -Path "CN=Computers,DC=techcorp,DC=local"
```

---

## Detection Command

Run this on your **Domain Controller** to detect Event 4741:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4741} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time      = $_.TimeCreated
        CreatedBy = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
        Computer  = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## What to Look For (SOC Analyst Tips)
- Computer accounts created by **non-admin users** (MachineAccountQuota default allows any domain user to create up to 10)
- Unusual computer names (random strings, mimicking real hostnames)
- Computer accounts created **outside working hours**
- New computer accounts that **never authenticate** (created but not used legitimately)

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Persistence / Lateral Movement |
| Technique | T1136.002 – Create Account: Domain Account |
