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

<img width="618" height="441" alt="image" src="https://github.com/user-attachments/assets/0d3fc66a-950d-43f8-9723-630c8f518c01" />

---

<img width="638" height="143" alt="WhatsApp Image 2026-07-12 at 4 27 32 PM" src="https://github.com/user-attachments/assets/a4c7c452-a348-4a81-80d7-1b7f22608622" />

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

<img width="983" height="511" alt="WhatsApp Image 2026-07-12 at 4 28 36 PM" src="https://github.com/user-attachments/assets/8624cda2-8d17-4edc-8bef-e13f1b0cb6d8" />

---

```powershell

Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/12/2026 3:07:28 PM
Event ID:      4756
Task Category: Security Group Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-G2FL349UD7V.techcorp.local
Description:
A member was added to a security-enabled universal group.

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
	Account Name:		Enterprise Admins
	Account Domain:		TECHCORP

Additional Information:
	Privileges:		-
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4756</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13826</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-12T22:07:28.9830601Z" />
    <EventRecordID>5236</EventRecordID>
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
