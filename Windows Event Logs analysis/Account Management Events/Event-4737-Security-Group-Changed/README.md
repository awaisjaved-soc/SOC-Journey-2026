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

<img width="412" height="464" alt="WhatsApp Image 2026-07-12 at 2 45 23 PM" src="https://github.com/user-attachments/assets/39b58f63-1750-4be4-8a72-4ddaf83a40ab" />

---
<img width="622" height="49" alt="WhatsApp Image 2026-07-12 at 2 44 10 PM" src="https://github.com/user-attachments/assets/01216eda-93a7-415d-8419-27fe3974894e" />

---

## Lab Method 2 – PowerShell

```powershell
Set-ADGroup -Identity "Domain Admins" -Description "Group modified in SOC Lab"
```

---

<img width="637" height="441" alt="WhatsApp Image 2026-07-12 at 2 43 34 PM" src="https://github.com/user-attachments/assets/dc7f2623-d436-481c-a65c-d21af6c2c3b8" />

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
<img width="984" height="511" alt="image" src="https://github.com/user-attachments/assets/0c888d4d-91ea-45ed-b202-9e8c73567dda" />

---
```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/12/2026 2:45:46 PM
Event ID:      4737
Task Category: Security Group Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-G2FL349UD7V.techcorp.local
Description:
A security-enabled global group was changed.

Subject:
	Security ID:		TECHCORP\Administrator
	Account Name:		Administrator
	Account Domain:		TECHCORP
	Logon ID:		0x9745A

Group:
	Security ID:		TECHCORP\Domain Admins
	Group Name:		Domain Admins
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
    <EventID>4737</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13826</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-12T21:45:46.0992636Z" />
    <EventRecordID>4953</EventRecordID>
    <Correlation />
    <Execution ProcessID="688" ThreadID="2496" />
    <Channel>Security</Channel>
    <Computer>WIN-G2FL349UD7V.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserName">Domain Admins</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetSid">S-1-5-21-2093721230-1860313452-4243889928-512</Data>
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
