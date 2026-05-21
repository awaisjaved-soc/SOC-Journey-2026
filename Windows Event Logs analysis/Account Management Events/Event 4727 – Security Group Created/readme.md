

### **Event 4727 – Security Group Created** (High Severity)

**What it means:**  
A new security group was created.

**SOC Importance:** High — Attackers create groups to organize compromised accounts or escalate privileges.


#### **Method 1: Using PowerShell (Recommended)**

Open **PowerShell as Administrator** and run:

```powershell
# Create a suspicious group (this will generate Event 4727)
New-ADGroup -Name "Suspicious_HelpDesk" `
            -GroupScope Global `
            -GroupCategory Security `
            -Description "Created by attacker for privilege escalation"
```

#### **Method 2: Using GUI (Active Directory Users and Computers)**

1. Press `Win + R` → type `dsa.msc` → Enter
2. Go to your domain → Right-click on an OU (e.g., IT or Users) → **New** → **Group**
3. Group name: `Suspicious_HelpDesk`
4. Group scope: **Global**
5. Group type: **Security**
6. Click **OK**

---

### **Check the Event (4727)**

On the **Domain Controller**, open **Event Viewer**:

- Go to **Windows Logs** → **Security**
- Filter by **Event ID 4727**

You should see the event with details like:
- Who created the group
- Group name (`Suspicious_HelpDesk`)
- Group scope and type

---



<img width="627" height="438" alt="image" src="https://github.com/user-attachments/assets/cfda7ec9-e943-4071-b421-d513dadc3ddb" />

---
<img width="731" height="442" alt="image" src="https://github.com/user-attachments/assets/196a7559-3943-411a-9307-c049607bbf58" />

---

### Detection Method
```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4727
} -MaxEvents 10 | 
Select TimeCreated, 
       @{Name='CreatedBy';Expression={$_.Properties[1].Value}}, 
       @{Name='GroupName';Expression={$_.Properties[0].Value}}, 
       @{Name='GroupScope';Expression={$_.Properties[2].Value}} | 
Format-Table -AutoSize
```

---
<img width="974" height="510" alt="image" src="https://github.com/user-attachments/assets/d7c12261-c5c0-4f87-ba8c-4c6c25c14649" />

---
```powershell

Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          5/20/2026 6:00:00 PM
Event ID:      4727
Task Category: Security Group Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-N4LQQSU0MFA.techcorp.local
Description:
A security-enabled global group was created.

Subject:
	Security ID:		TECHCORP\administrator
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x41618

New Group:
	Security ID:		TECHCORP\Suspicious_HelpDesk
	Group Name:		Suspicious_HelpDesk
	Group Domain:		TECHCORP

Attributes:
	SAM Account Name:	Suspicious_HelpDesk
	SID History:		-

Additional Information:
	Privileges:		-
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4727</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13826</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-05-21T01:00:00.7452414Z" />
    <EventRecordID>10950</EventRecordID>
    <Correlation />
    <Execution ProcessID="620" ThreadID="2780" />
    <Channel>Security</Channel>
    <Computer>WIN-N4LQQSU0MFA.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserName">Suspicious_HelpDesk</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetSid">S-1-5-21-3567083499-616298403-1270708564-1126</Data>
    <Data Name="SubjectUserSid">S-1-5-21-3567083499-616298403-1270708564-500</Data>
    <Data Name="SubjectUserName">administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x41618</Data>
    <Data Name="PrivilegeList">-</Data>
    <Data Name="SamAccountName">Suspicious_HelpDesk</Data>
    <Data Name="SidHistory">-</Data>
  </EventData>
</Event>
```
---

