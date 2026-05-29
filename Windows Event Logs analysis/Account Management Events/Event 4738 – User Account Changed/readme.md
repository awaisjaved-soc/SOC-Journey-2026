

### **3. Event 4738 – User Account Changed** (Medium)

**What it means:** Properties of a user account were modified.

**PowerShell Method:**
```powershell
Set-ADUser -Identity "mannual" `
    -Title "Senior Engineer" `
    -Department "IT Operations" `
    -Description "Modified by SOC Lab"
```

**GUI Method:**
1. Open **Computer Management** → **Users**
2. Right-click user → **Properties**
3. Change settings (e.g., Password never expires)

---
<img width="622" height="448" alt="WhatsApp Image 2026-05-23 at 6 53 04 PM" src="https://github.com/user-attachments/assets/b5bb1e18-2d54-497a-91ad-66fbc6ce1512" />


**Detection Command:**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4738
} -MaxEvents 10 | 
Select TimeCreated, 
       @{Name='ChangedBy';Expression={$_.Properties[1].Value}}, 
       @{Name='TargetUser';Expression={$_.Properties[0].Value}} | 
Format-Table -AutoSize
```
<img width="729" height="460" alt="WhatsApp Image 2026-05-23 at 6 56 33 PM" src="https://github.com/user-attachments/assets/71a611f6-676e-4a09-b578-5485ddf4baaa" />

---

```powershell

Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          5/21/2026 9:08:38 PM
Event ID:      4738
Task Category: User Account Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-N4LQQSU0MFA.techcorp.local
Description:
A user account was changed.

Subject:
	Security ID:		TECHCORP\administrator
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x62B699

Target Account:
	Security ID:		TECHCORP\mannual
	Account Name:		mannual
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
	Old UAC Value:		-
	New UAC Value:		-
	User Account Control:	-
	User Parameters:	-
	SID History:		-
	Logon Hours:		-

Additional Information:
	Privileges:		-
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4738</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13824</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-05-22T04:08:38.0433945Z" />
    <EventRecordID>16308</EventRecordID>
    <Correlation />
    <Execution ProcessID="624" ThreadID="2980" />
    <Channel>Security</Channel>
    <Computer>WIN-N4LQQSU0MFA.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="Dummy">-</Data>
    <Data Name="TargetUserName">mannual</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetSid">S-1-5-21-3567083499-616298403-1270708564-1122</Data>
    <Data Name="SubjectUserSid">S-1-5-21-3567083499-616298403-1270708564-500</Data>
    <Data Name="SubjectUserName">administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x62b699</Data>
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
    <Data Name="OldUacValue">-</Data>
    <Data Name="NewUacValue">-</Data>
    <Data Name="UserAccountControl">-</Data>
    <Data Name="UserParameters">-</Data>
    <Data Name="SidHistory">-</Data>
    <Data Name="LogonHours">-</Data>
  </EventData>
</Event>
```
---

