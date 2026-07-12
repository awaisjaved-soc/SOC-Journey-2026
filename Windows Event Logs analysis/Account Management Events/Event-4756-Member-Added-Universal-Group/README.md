# Event 4756 – Member Added to Security-Enabled Universal Group

## Event Description
This event is logged when a **user, computer, or group is added** to a security-enabled Universal Group.  
Universal Groups have **forest-wide scope**, so membership changes can affect access across all domains in the forest.

## SOC Relevance
**High severity.** Adding accounts to Universal Groups can grant **broad cross-domain privileges**. Attackers may exploit this for privilege escalation — especially if the Universal Group is nested inside high-privilege groups like Domain Admins or Enterprise Admins.

---

## Lab Method 1 – Manual GUI

1. Open **Active Directory Users and Computers** (`dsa.msc`)
2. Right-click the Universal Group (e.g., `UniversalTestGroup`) → **Properties**
3. Go to the **Members** tab
4. Click **Add** → Enter a username (e.g., `testuser01`) → **OK**

---

## Lab Method 2 – PowerShell

```powershell
Add-ADGroupMember -Identity "UniversalTestGroup" -Members "testuser01"
```

---

## Detection Command

Run this on your **Domain Controller** to detect Event 4756:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4756} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time      = $_.TimeCreated
        AddedBy   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
        AddedUser = ($xml.Event.EventData.Data | Where {$_.Name -eq 'MemberName'}).'#text'
        GroupName = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## What to Look For (SOC Analyst Tips)
- Users added to Universal Groups that are **nested in privileged groups**
- Additions performed by **non-admin accounts** (SubjectUserName)
- **Service accounts or computer accounts** added unexpectedly
- Additions happening **outside business hours** or during incidents

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Privilege Escalation / Persistence |
| Technique | T1098.007 – Account Manipulation: Additional Local or Domain Group Membership |
