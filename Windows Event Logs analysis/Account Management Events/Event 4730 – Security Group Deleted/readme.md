

### **Event 4730 – Security Group Deleted** (High Severity)

**What it means:**  
A security group was deleted.

**SOC Relevance:**  
Attackers delete groups after using them to hide evidence.

#### **PowerShell Method**

```powershell
# Delete the group
Remove-ADGroup -Identity "SOC_Admins" -Confirm:$false
```

**Explanation:**  
- `Remove-ADGroup` → Deletes the group permanently
- `-Identity` → Name of the group to delete

#### **Manual GUI Method**

1. Open `dsa.msc`
2. Find the group `SOC_Admins`
3. Right-click the group → **Delete** → Yes

---
<img width="756" height="531" alt="image" src="https://github.com/user-attachments/assets/63dc1ab7-06fa-4951-9008-0f369e5aacba" />


---

<img width="629" height="442" alt="image" src="https://github.com/user-attachments/assets/4d9e69fb-6340-4c2e-a3d0-44e9b1231d81" />

---

```powershell

### Detection Method:
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4730
} -MaxEvents 10 | 
Select TimeCreated, 
       @{Name='CreatedBy';Expression={$_.Properties[1].Value}}, 
       @{Name='GroupName';Expression={$_.Properties[0].Value}}, 
       @{Name='GroupScope';Expression={$_.Properties[2].Value}} | 
Format-Table -AutoSize

```
<img width="631" height="438" alt="image" src="https://github.com/user-attachments/assets/d1dafb69-46f8-48c1-9242-422c8cb17567" />

---


```powershell

Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          5/20/2026 6:33:21 PM
Event ID:      4730
Task Category: Security Group Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-N4LQQSU0MFA.techcorp.local
Description:
A security-enabled global group was deleted.

Subject:
	Security ID:		TECHCORP\administrator
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x41618

Deleted Group:
	Security ID:		TECHCORP\SOC_Admins
	Group Name:		SOC_Admins
	Group Domain:		TECHCORP

Additional Information:
	Privileges:		-
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4730</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13826</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-05-21T01:33:21.5749030Z" />
    <EventRecordID>11240</EventRecordID>
    <Correlation />
    <Execution ProcessID="620" ThreadID="2032" />
    <Channel>Security</Channel>
    <Computer>WIN-N4LQQSU0MFA.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
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
These images are mixed and the method is same.
In the images group names are different and in command the names are different its because i practice these things so the screenshots and commands are mixed !!
---

