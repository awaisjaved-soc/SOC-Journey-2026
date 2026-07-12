# Event 4737 – Security Group Changed

## Event Description
This event is generated when the **properties** of a security group are modified (e.g., description, group scope, or other attributes changed).  
> ⚠️ This event does **not** log member addition or removal — those are separate events (4728, 4729, etc.)

## SOC Relevance
Attackers may modify group properties to maintain persistence or hide unauthorized changes. Monitoring this event helps detect stealthy group modifications that don't involve adding/removing members.

---

## Lab Method 1 – Manual GUI

1. Open **Active Directory Users and Computers** (`dsa.msc`)
2. Locate any security group (e.g., `Domain Admins`)
3. Right-click → **Properties**
4. Change the **Description** field or any other attribute
5. Click **Apply** → **OK**

---

## Lab Method 2 – PowerShell

```powershell
Set-ADGroup -Identity "Domain Admins" -Description "Group modified in SOC Lab"
```

---

## Detection Command

Run this on your **Domain Controller** to detect Event 4737:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4737} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        ModifiedBy  = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
        GroupName   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## What to Look For (SOC Analyst Tips)
- Unexpected changes to **high-privilege groups** (Domain Admins, Enterprise Admins)
- Changes made **outside business hours**
- `SubjectUserName` that is not a known admin account
- Multiple group modifications in a short time window

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Persistence / Defense Evasion |
| Technique | T1098 – Account Manipulation |
