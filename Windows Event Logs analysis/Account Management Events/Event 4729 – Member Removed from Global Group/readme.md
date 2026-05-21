
### **Event 4729 – Member Removed from Group** (Medium Severity)

**What it means:**  
A user was removed from a security group.

**SOC Relevance:**  
This can be normal HR work or an attacker removing himself after using elevated privileges (covering tracks).

#### **PowerShell Method**

```powershell
# Remove user "suspicioususer" from group "Suspicious_HelpDesks"
Remove-ADGroupMember -Identity "Suspicious_HelpDesk" -Members "suspicioususer" -Confirm:$false
```

**Explanation:**  
- `Remove-ADGroupMember` → Removes a member from a group
- `-Identity` → Name of the group
- `-Members` → User to remove
- `-Confirm:$false` → No confirmation prompt
- 

#### **Manual GUI Method**

1. Open `dsa.msc` (Active Directory Users and Computers)
2. Find the group `Suspicious_HelpDesk`
3. Double-click the group → Go to **Members** tab
4. Select `suspicioususer` → Click **Remove** → OK

---

<img width="753" height="529" alt="image" src="https://github.com/user-attachments/assets/ac0a4ffd-b6e1-46d2-95a7-b9552c7462dc" />

---


<img width="638" height="467" alt="image" src="https://github.com/user-attachments/assets/495d3d61-338c-4ef8-b5f0-6691bbe39a0b" />

---


<img width="399" height="454" alt="image" src="https://github.com/user-attachments/assets/f170cf9e-2750-4c30-bf0f-8ae692ac9fdf" />
---

<img width="967" height="404" alt="image" src="https://github.com/user-attachments/assets/f9a61505-4dcb-41d3-96f8-0ea64956175b" />

---
```powershell
### Detection Method:
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4729
} -MaxEvents 10 | 
Select TimeCreated, 
       @{Name='CreatedBy';Expression={$_.Properties[1].Value}}, 
       @{Name='GroupName';Expression={$_.Properties[0].Value}}, 
       @{Name='GroupScope';Expression={$_.Properties[2].Value}} | 
Format-Table -AutoSize

```
---
```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          5/20/2026 6:27:06 PM
Event ID:      4729
Task Category: Security Group Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-N4LQQSU0MFA.techcorp.local
Description:
A member was removed from a security-enabled global group.

Subject:
	Security ID:		TECHCORP\administrator
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x41618

Member:
	Security ID:		TECHCORP\mannual
	Account Name:		CN=mannual user,OU=IT,DC=techcorp,DC=local

Group:
	Security ID:		TECHCORP\SOC_Admins
	Group Name:		SOC_Admins
	Group Domain:		TECHCORP

Additional Information:
	Privileges:		-
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4729</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13826</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-05-21T01:27:06.3807400Z" />
    <EventRecordID>11192</EventRecordID>
    <Correlation />
    <Execution ProcessID="620" ThreadID="2032" />
    <Channel>Security</Channel>
    <Computer>WIN-N4LQQSU0MFA.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="MemberName">CN=mannual user,OU=IT,DC=techcorp,DC=local</Data>
    <Data Name="MemberSid">S-1-5-21-3567083499-616298403-1270708564-1122</Data>
    <Data Name="TargetUserName">SOC_Admins</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetSid">S-1-5-21-3567083499-616298403-1270708564-1125</Data>
    <Data Name="SubjectUserSid">S-1-5-21-3567083499-616298403-1270708564-500</Data>
    <Data Name="SubjectUserName">administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x41618</Data>
    <Data Name="PrivilegeList">-</Data>
  </EventData>
</Event>
```
