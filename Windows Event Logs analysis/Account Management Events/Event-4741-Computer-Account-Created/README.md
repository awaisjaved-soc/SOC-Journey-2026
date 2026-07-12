# Event 4741 – Computer Account Created

## Event Description
This event is logged when a **new computer account** is added to the Active Directory domain.  
Every machine that joins the domain gets a computer account — but attackers can also create **rogue computer accounts** for malicious purposes.

## SOC Relevance
Attackers create rogue computer accounts to enable **lateral movement**, **persistence**, or to abuse Kerberos (e.g., Resource-Based Constrained Delegation attacks like MachineAccountQuota abuse).

---

## Lab Method 1 – Manual GUI

1. Open **Active Directory Users and Computers** (`dsa.msc`)
2. Navigate to the **Computers** container (or any OU)
3. Right-click → **New** → **Computer**
4. Enter a computer name (e.g., `ROGUE-PC-01`)
5. Click **OK**

---
<img width="485" height="405" alt="image" src="https://github.com/user-attachments/assets/b1e38225-11a2-4ef7-8c73-3dd583b5977f" />

---

<img width="752" height="522" alt="image" src="https://github.com/user-attachments/assets/e5e33299-3069-420e-b848-bdfca0c05a04" />

---

<img width="625" height="440" alt="image" src="https://github.com/user-attachments/assets/341c4b67-5fa9-454b-a50b-450cb60a2459" />

---

## Lab Method 2 – PowerShell

```powershell
New-ADComputer -Name "ROGUE-PC-01" -Path "CN=Computers,DC=techcorp,DC=local"
```

---

<img width="627" height="146" alt="image" src="https://github.com/user-attachments/assets/5d00502e-3248-413c-97dc-4644da480428" />

---

## Detection Command

Run this on your **Domain Controller** to detect Event 4741:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4741} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time      = $_.TimeCreated
        CreatedBy = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
        Computer  = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```
---
<img width="980" height="513" alt="WhatsApp Image 2026-07-12 at 4 08 22 PM" src="https://github.com/user-attachments/assets/ff4b4f46-5122-4624-9f89-34a42af925d9" />

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/12/2026 2:52:53 PM
Event ID:      4741
Task Category: Computer Account Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-G2FL349UD7V.techcorp.local
Description:
A computer account was created.

Subject:
	Security ID:		TECHCORP\Administrator
	Account Name:		Administrator
	Account Domain:		TECHCORP
	Logon ID:		0x9745A

New Computer Account:
	Security ID:		TECHCORP\TEST-PC-01$
	Account Name:		TEST-PC-01$
	Account Domain:		TECHCORP

Attributes:
	SAM Account Name:	TEST-PC-01$
	Display Name:		-
	User Principal Name:	-
	Home Directory:		-
	Home Drive:		-
	Script Path:		-
	Profile Path:		-
	User Workstations:	-
	Password Last Set:	<never>
	Account Expires:		<never>
	Primary Group ID:	515
	AllowedToDelegateTo:	-
	Old UAC Value:		0x0
	New UAC Value:		0x81
	User Account Control:	
		Account Disabled
		'Workstation Trust Account' - Enabled
	User Parameters:	-
	SID History:		-
	Logon Hours:		<value not set>
	DNS Host Name:		-
	Service Principal Names:	-

Additional Information:
	Privileges		-
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4741</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13825</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-12T21:52:53.1552787Z" />
    <EventRecordID>5051</EventRecordID>
    <Correlation />
    <Execution ProcessID="688" ThreadID="1128" />
    <Channel>Security</Channel>
    <Computer>WIN-G2FL349UD7V.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserName">TEST-PC-01$</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetSid">S-1-5-21-2093721230-1860313452-4243889928-1117</Data>
    <Data Name="SubjectUserSid">S-1-5-21-2093721230-1860313452-4243889928-500</Data>
    <Data Name="SubjectUserName">Administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x9745a</Data>
    <Data Name="PrivilegeList">-</Data>
    <Data Name="SamAccountName">TEST-PC-01$</Data>
    <Data Name="DisplayName">-</Data>
    <Data Name="UserPrincipalName">-</Data>
    <Data Name="HomeDirectory">-</Data>
    <Data Name="HomePath">-</Data>
    <Data Name="ScriptPath">-</Data>
    <Data Name="ProfilePath">-</Data>
    <Data Name="UserWorkstations">-</Data>
    <Data Name="PasswordLastSet">%%1794</Data>
    <Data Name="AccountExpires">%%1794</Data>
    <Data Name="PrimaryGroupId">515</Data>
    <Data Name="AllowedToDelegateTo">-</Data>
    <Data Name="OldUacValue">0x0</Data>
    <Data Name="NewUacValue">0x81</Data>
    <Data Name="UserAccountControl">
		%%2080
		%%2087</Data>
    <Data Name="UserParameters">-</Data>
    <Data Name="SidHistory">-</Data>
    <Data Name="LogonHours">%%1793</Data>
    <Data Name="DnsHostName">-</Data>
    <Data Name="ServicePrincipalNames">-</Data>
  </EventData>
</Event>
```

---

## What to Look For (SOC Analyst Tips)
- Computer accounts created by **non-admin users** (MachineAccountQuota default allows any domain user to create up to 10)
- Unusual computer names (random strings, mimicking real hostnames)
- Computer accounts created **outside working hours**
- New computer accounts that **never authenticate** (created but not used legitimately)

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Persistence / Lateral Movement |
| Technique | T1136.002 – Create Account: Domain Account |
