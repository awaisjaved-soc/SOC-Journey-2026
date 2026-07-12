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

<img width="624" height="441" alt="image" src="https://github.com/user-attachments/assets/dc02d35f-b04a-449c-aba1-3e31c7e4191d" />

---

<img width="632" height="139" alt="WhatsApp Image 2026-07-12 at 4 30 37 PM" src="https://github.com/user-attachments/assets/a9b04969-8e3b-41d1-a58b-6a8bda82b485" />

---
## Lab Method 2 – PowerShell

```powershell
Remove-ADGroupMember -Identity "UniversalTestGroup" -Members "testuser01" -Confirm:$false
```

---

<img width="401" height="457" alt="WhatsApp Image 2026-07-12 at 4 31 18 PM" src="https://github.com/user-attachments/assets/7c476cad-10f9-457f-ad4a-daacdb2ca600" />

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

<img width="984" height="511" alt="image" src="https://github.com/user-attachments/assets/ba097da8-58e3-45b9-a35d-8fa3624bfe43" />


---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/12/2026 3:08:41 PM
Event ID:      4757
Task Category: Security Group Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-G2FL349UD7V.techcorp.local
Description:
A member was removed from a security-enabled universal group.

Subject:
	Security ID:		TECHCORP\Administrator
	Account Name:		Administrator
	Account Domain:		TECHCORP
	Logon ID:		0x9745A

Member:
	Security ID:		TECHCORP\emmathompson
	Account Name:		CN=Emma Thompson,OU=Employees,DC=techcorp,DC=local

Group:
	Security ID:		TECHCORP\Enterprise Admins
	Group Name:		Enterprise Admins
	Group Domain:		TECHCORP

Additional Information:
	Privileges:		-
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4757</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13826</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-12T22:08:41.7763856Z" />
    <EventRecordID>5246</EventRecordID>
    <Correlation />
    <Execution ProcessID="688" ThreadID="1128" />
    <Channel>Security</Channel>
    <Computer>WIN-G2FL349UD7V.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="MemberName">CN=Emma Thompson,OU=Employees,DC=techcorp,DC=local</Data>
    <Data Name="MemberSid">S-1-5-21-2093721230-1860313452-4243889928-1104</Data>
    <Data Name="TargetUserName">Enterprise Admins</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetSid">S-1-5-21-2093721230-1860313452-4243889928-519</Data>
    <Data Name="SubjectUserSid">S-1-5-21-2093721230-1860313452-4243889928-500</Data>
    <Data Name="SubjectUserName">Administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x9745a</Data>
    <Data Name="PrivilegeList">-</Data>
  </EventData>
</Event>
```

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
