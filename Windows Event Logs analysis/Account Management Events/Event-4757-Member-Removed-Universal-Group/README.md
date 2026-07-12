# Event 4757 – Member Removed from Security-Enabled Universal Group

## Event Description
This event is logged when a **user, computer, or group is removed** from a security-enabled Universal Group.

## SOC Relevance
**Medium severity.** While often legitimate (offboarding, cleanup), attackers may remove members from Universal Groups to **disrupt access**, **lock out defenders**, or **clean up evidence** after adding themselves earlier. Correlate this with Event 4756 (member added) for full picture.

---

## Lab Method 1 – Manual GUI

1. Open **Active Directory Users and Computers** (`dsa.msc`)
2. Right-click the Universal Group (e.g., `UniversalTestGroup`) → **Properties**
3. Go to the **Members** tab
4. Select a user → Click **Remove** → **OK**

---

## Lab Method 2 – PowerShell

```powershell
Remove-ADGroupMember -Identity "UniversalTestGroup" -Members "testuser01" -Confirm:$false
```

---

## Detection Command

Run this on your **Domain Controller** to detect Event 4757:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4757} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        RemovedBy   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
        RemovedUser = ($xml.Event.EventData.Data | Where {$_.Name -eq 'MemberName'}).'#text'
        GroupName   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## What to Look For (SOC Analyst Tips)
- Removal of **admin or security team accounts** from Universal Groups (locking defenders out)
- Quick **add → remove pattern** (4756 followed by 4757 for same user = cover tracks)
- Removals performed by **unexpected SubjectUserName**
- Mass removals affecting multiple members at once

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Defense Evasion / Impact |
| Technique | T1070 – Indicator Removal / T1531 – Account Access Removal |
