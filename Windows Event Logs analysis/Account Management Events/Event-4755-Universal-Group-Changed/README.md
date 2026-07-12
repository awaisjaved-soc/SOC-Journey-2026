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

<img width="626" height="437" alt="image" src="https://github.com/user-attachments/assets/4bd47aed-1818-4f49-868c-c5edfb524025" />

---

<img width="636" height="186" alt="WhatsApp Image 2026-07-12 at 4 23 21 PM" src="https://github.com/user-attachments/assets/7bb7f56f-07d7-4318-84d5-fe568cde8879" />

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

<img width="981" height="512" alt="WhatsApp Image 2026-07-12 at 4 24 05 PM" src="https://github.com/user-attachments/assets/f908c21b-3028-4064-bf30-fa1baa0f8db6" />

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/12/2026 3:08:41 PM
Event ID:      4755
Task Category: Security Group Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-G2FL349UD7V.techcorp.local
Description:
A security-enabled universal group was changed.

Subject:
	Security ID:		TECHCORP\Administrator
	Account Name:		Administrator
	Account Domain:		TECHCORP
	Logon ID:		0x9745A

Group:
	Security ID:		TECHCORP\Enterprise Admins
	Group Name:		Enterprise Admins
	Group Domain:		TECHCORP

Changed Attributes:
	SAM Account Name:	-
	SID History:		-

Additional Information:
	Privileges:		-
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4755</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13826</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-12T22:08:41.7763402Z" />
    <EventRecordID>5245</EventRecordID>
    <Correlation />
    <Execution ProcessID="688" ThreadID="1128" />
    <Channel>Security</Channel>
    <Computer>WIN-G2FL349UD7V.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserName">Enterprise Admins</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetSid">S-1-5-21-2093721230-1860313452-4243889928-519</Data>
    <Data Name="SubjectUserSid">S-1-5-21-2093721230-1860313452-4243889928-500</Data>
    <Data Name="SubjectUserName">Administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x9745a</Data>
    <Data Name="PrivilegeList">-</Data>
    <Data Name="SamAccountName">-</Data>
    <Data Name="SidHistory">-</Data>
  </EventData>
</Event>
```

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
