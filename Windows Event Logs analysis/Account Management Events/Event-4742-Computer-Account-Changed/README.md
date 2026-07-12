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

<img width="634" height="450" alt="image" src="https://github.com/user-attachments/assets/a3f9c65c-0451-4c50-9f2d-c130693d7c77" />

---

<img width="629" height="212" alt="image" src="https://github.com/user-attachments/assets/e59dcb7d-ae71-489e-b351-76530e4a18ab" />

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

<img width="984" height="513" alt="WhatsApp Image 2026-07-12 at 4 13 35 PM" src="https://github.com/user-attachments/assets/6e709ce0-1dcd-458d-80ba-06dffb1d9ea4" />

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/12/2026 3:05:28 PM
Event ID:      4742
Task Category: Computer Account Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-G2FL349UD7V.techcorp.local
Description:
A computer account was changed.

Subject:
	Security ID:		TECHCORP\Administrator
	Account Name:		Administrator
	Account Domain:		TECHCORP
	Logon ID:		0x9745A

Computer Account That Was Changed:
	Security ID:		TECHCORP\TEST-COMPUTER$
	Account Name:		TEST-COMPUTER$
	Account Domain:		TECHCORP

Changed Attributes:
	SAM Account Name:	-
	Display Name:		-
	User Principal Name:	-
	Home Directory:		-
	Home Drive:		-
	Script Path:		-
	Profile Path:		-
	User Workstations:	-
	Password Last Set:	-
	Account Expires:		-
	Primary Group ID:	-
	AllowedToDelegateTo:	-
	Old UAC Value:		0x84
	New UAC Value:		0x85
	User Account Control:	
		Account Disabled
	User Parameters:	-
	SID History:		-
	Logon Hours:		-
	DNS Host Name:		-
	Service Principal Names:	-

Additional Information:
	Privileges:		-
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4742</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13825</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-12T22:05:28.2233010Z" />
    <EventRecordID>5199</EventRecordID>
    <Correlation />
    <Execution ProcessID="688" ThreadID="2076" />
    <Channel>Security</Channel>
    <Computer>WIN-G2FL349UD7V.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="ComputerAccountChange">-</Data>
    <Data Name="TargetUserName">TEST-COMPUTER$</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetSid">S-1-5-21-2093721230-1860313452-4243889928-1116</Data>
    <Data Name="SubjectUserSid">S-1-5-21-2093721230-1860313452-4243889928-500</Data>
    <Data Name="SubjectUserName">Administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x9745a</Data>
    <Data Name="PrivilegeList">-</Data>
    <Data Name="SamAccountName">-</Data>
    <Data Name="DisplayName">-</Data>
    <Data Name="UserPrincipalName">-</Data>
    <Data Name="HomeDirectory">-</Data>
    <Data Name="HomePath">-</Data>
    <Data Name="ScriptPath">-</Data>
    <Data Name="ProfilePath">-</Data>
    <Data Name="UserWorkstations">-</Data>
    <Data Name="PasswordLastSet">-</Data>
    <Data Name="AccountExpires">-</Data>
    <Data Name="PrimaryGroupId">-</Data>
    <Data Name="AllowedToDelegateTo">-</Data>
    <Data Name="OldUacValue">0x84</Data>
    <Data Name="NewUacValue">0x85</Data>
    <Data Name="UserAccountControl">
		%%2080</Data>
    <Data Name="UserParameters">-</Data>
    <Data Name="SidHistory">-</Data>
    <Data Name="LogonHours">-</Data>
    <Data Name="DnsHostName">-</Data>
    <Data Name="ServicePrincipalNames">-</Data>
  </EventData>
</Event>
```

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
