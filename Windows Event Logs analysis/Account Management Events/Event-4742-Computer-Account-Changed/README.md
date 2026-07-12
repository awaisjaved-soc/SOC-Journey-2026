# Event 4742 – Computer Account Changed

## Event Description
This event is generated when **properties of an existing computer account** are modified in Active Directory.  
This includes changes to description, password, flags, delegation settings, and other attributes.

## SOC Relevance
Attackers modify computer accounts to **blend in**, change delegation settings for **Kerberos abuse**, or alter attributes to maintain stealthy access. Particularly dangerous when `msDS-AllowedToActOnBehalfOfOtherIdentity` is modified (RBCD attack).

---

## Lab Method 1 – Manual GUI

1. Open **Active Directory Users and Computers** (`dsa.msc`)
2. Locate an existing computer account (e.g., `WIN10-PC`)
3. Right-click → **Properties**
4. Change the **Description** field or any attribute
5. Click **Apply** → **OK**

---

## Lab Method 2 – PowerShell

```powershell
Set-ADComputer -Identity "TEST-PC-01" -Description "Modified by attacker"
```

---

## Detection Command

Run this on your **Domain Controller** to detect Event 4742:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4742} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time         = $_.TimeCreated
        ModifiedBy   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
        ComputerName = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## What to Look For (SOC Analyst Tips)
- Changes to **delegation attributes** (`TrustedForDelegation`, `TrustedToAuthForDelegation`)
- Modifications to **high-value machine accounts** (servers, DCs)
- Changes made by **non-admin accounts**
- Repeated modifications in short time spans

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Privilege Escalation / Persistence |
| Technique | T1098 – Account Manipulation |
