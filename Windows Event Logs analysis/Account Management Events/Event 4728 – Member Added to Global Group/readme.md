

### **Event 4728 – Member Added to Group (High/Critical)**

**What it means:**  
A user was added to a security group.  
If the group has high privileges (like Administrators or Domain Admins), this is a **major red flag**.

---

### **How to Add a User to the Group**

#### **Method 1: PowerShell (Recommended for Lab)**

```powershell
# Add user "Suspicious User" to the group "Suspicious_HelpDesk"
Add-ADGroupMember -Identity "Suspicious_HelpDesk" -Members "Suspicious User"
```

**Explanation:**
- `Add-ADGroupMember` → Command to add members to a group
- `-Identity` → Name of the group
- `-Members` → Username you want to add

---

<img width="637" height="464" alt="image" src="https://github.com/user-attachments/assets/86313f57-2411-4418-abdb-c52326167ce9" />


#### **Method 2: GUI (Manual Way)**

1. Open **Active Directory Users and Computers** (`dsa.msc`)
2. Find your group (Suspicious_HelpDesk`)
3. Double-click the group
4. Go to **Members** tab → Click **Add**
5. Type the username (`Suspicious User`) → Click **Check Names** → **OK**
6. Click **Apply** → **OK**

---
<img width="406" height="453" alt="image" src="https://github.com/user-attachments/assets/1534ee36-d97a-422c-94f5-17a281d39b21" />


### **Check the Event (4728)**

Open **Event Viewer** → **Windows Logs** → **Security**

Filter by **Event ID 4728**

You will see details like:
- Who added the member (`SubjectUserName`)
- Which user was added (`MemberName`)
- Which group (`GroupName`)

---
<img width="753" height="529" alt="image" src="https://github.com/user-attachments/assets/2e9af1b5-c3c6-4b8c-a506-e2ffc403348c" />

### Detection Method:
```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4728
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
Date:          5/20/2026 6:10:25 PM
Event ID:      4728
Task Category: Security Group Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-N4LQQSU0MFA.techcorp.local
Description:
A member was added to a security-enabled global group.

Subject:
	Security ID:		TECHCORP\administrator
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x41618

Member:
	Security ID:		TECHCORP\suspicioususer
	Account Name:		CN=Suspicious User,OU=IT,DC=techcorp,DC=local

Group:
	Security ID:		TECHCORP\Suspicious_HelpDesk
	Group Name:		Suspicious_HelpDesk
	Group Domain:		TECHCORP

Additional Information:
	Privileges:		-
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4728</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13826</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-05-21T01:10:25.4506227Z" />
    <EventRecordID>11049</EventRecordID>
    <Correlation />
    <Execution ProcessID="620" ThreadID="2032" />
    <Channel>Security</Channel>
    <Computer>WIN-N4LQQSU0MFA.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="MemberName">CN=Suspicious User,OU=IT,DC=techcorp,DC=local</Data>
    <Data Name="MemberSid">S-1-5-21-3567083499-616298403-1270708564-1116</Data>
    <Data Name="TargetUserName">Suspicious_HelpDesk</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetSid">S-1-5-21-3567083499-616298403-1270708564-1126</Data>
    <Data Name="SubjectUserSid">S-1-5-21-3567083499-616298403-1270708564-500</Data>
    <Data Name="SubjectUserName">administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x41618</Data>
    <Data Name="PrivilegeList">-</Data>
  </EventData>
</Event>
```
---

