


### **Event 4731 – Security-Enabled Local Group Created** (High Severity)

**What it means:**  
A new **local** security group was created on the machine.

**SOC Relevance:**  
Attackers create local groups for persistence or local privilege escalation on individual servers.

#### **PowerShell Method**

```powershell
# Create a local security group
New-LocalGroup -Name "LocalHackers" -Description "Local group created by attacker"
```

**Explanation:**  
- `New-LocalGroup` → Creates a new local group on the machine

#### **Manual GUI Method**

1. Press `Win + X` → **Computer Management**
2. Go to **Local Users and Groups** → **Groups**
3. Right-click → **New Group**
4. Group name: `LocalHackers`
5. Click **Create**
   
---

<img width="759" height="533" alt="image" src="https://github.com/user-attachments/assets/e06d7290-e7a0-4f63-bf65-179ce7007494" />


---

<img width="625" height="442" alt="image" src="https://github.com/user-attachments/assets/d27f94e0-c150-4674-b3eb-cbf4ddca7706" />

---

### Detection Method:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4731
} -MaxEvents 10 | 
Select TimeCreated, 
       @{Name='CreatedBy';Expression={$_.Properties[1].Value}}, 
       @{Name='GroupName';Expression={$_.Properties[0].Value}}, 
       @{Name='GroupScope';Expression={$_.Properties[2].Value}} | 
Format-Table -AutoSize
```
---
<img width="941" height="258" alt="image" src="https://github.com/user-attachments/assets/6440885b-e0a3-4c9d-b69d-f1c6bcda89c0" />

---

```powershell

Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          5/20/2026 6:35:58 PM
Event ID:      4731
Task Category: Security Group Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-N4LQQSU0MFA.techcorp.local
Description:
A security-enabled local group was created.

Subject:
	Security ID:		TECHCORP\administrator
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x41618

New Group:
	Security ID:		TECHCORP\LocalHackers
	Group Name:		LocalHackers
	Group Domain:		TECHCORP

Attributes:
	SAM Account Name:	LocalHackers
	SID History:		-

Additional Information:
	Privileges:		-
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4731</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13826</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-05-21T01:35:58.6978524Z" />
    <EventRecordID>11278</EventRecordID>
    <Correlation />
    <Execution ProcessID="620" ThreadID="4872" />
    <Channel>Security</Channel>
    <Computer>WIN-N4LQQSU0MFA.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserName">LocalHackers</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetSid">S-1-5-21-3567083499-616298403-1270708564-1127</Data>
    <Data Name="SubjectUserSid">S-1-5-21-3567083499-616298403-1270708564-500</Data>
    <Data Name="SubjectUserName">administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x41618</Data>
    <Data Name="PrivilegeList">-</Data>
    <Data Name="SamAccountName">LocalHackers</Data>
    <Data Name="SidHistory">-</Data>
  </EventData>
</Event>
```

---






