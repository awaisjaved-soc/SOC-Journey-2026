# Event 4755 – Security-Enabled Universal Group Changed

## Event Description
This event is generated when the **properties of a security-enabled Universal Group** are modified.  
Universal Groups can span **multiple domains** in a forest, making them particularly powerful — and a high-value target for attackers.

## SOC Relevance
Universal Groups are commonly used in **multi-domain Active Directory environments** for cross-domain access control. Unauthorized modifications can silently expand access across the entire forest. This event helps track stealthy attribute changes that don't involve membership changes.

---

## Lab Method 1 – Manual GUI

1. Open **Active Directory Users and Computers** (`dsa.msc`)
2. Locate a **Universal** security group (check group scope in Properties → General)
3. Right-click → **Properties**
4. Change the **Description** or any attribute
5. Click **Apply** → **OK**

> 💡 To create a Universal Group for testing:  
> Right-click an OU → New → Group → Set **Group scope** to **Universal** and **Group type** to **Security**

---

## Lab Method 2 – PowerShell

```powershell
# First create a Universal group for testing (if not already present)
New-ADGroup -Name "UniversalTestGroup" -GroupScope Universal -GroupCategory Security -Path "OU=IT,DC=techcorp,DC=local"

# Then modify it to trigger Event 4755
Set-ADGroup -Identity "UniversalTestGroup" -Description "Changed in SOC Lab"
```

---

## Detection Command

Run this on your **Domain Controller** to detect Event 4755:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4755} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time       = $_.TimeCreated
        ModifiedBy = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
        GroupName  = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```

---

## What to Look For (SOC Analyst Tips)
- Changes to Universal Groups that control **cross-domain access**
- Scope changes from Global/Domain Local → **Universal** (expands reach)
- Modifications by **non-privileged accounts**
- Changes outside of **approved change windows**

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Persistence / Defense Evasion |
| Technique | T1098 – Account Manipulation |
