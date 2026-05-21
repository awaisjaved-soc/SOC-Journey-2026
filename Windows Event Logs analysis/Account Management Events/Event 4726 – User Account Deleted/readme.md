

### **Event 4726 – User Account Deleted** (High Severity)

**What it means:**  
This event is logged when a user account is deleted from the system.

**SOC Importance:** High — Attackers delete accounts to cover their tracks after using them.

#### **Method 1: Using PowerShell (Recommended)**

```powershell
# Delete a user account
Remove-LocalUser -Name "TestUser01"
```

**Explanation:**
- `Remove-LocalUser` → Deletes the user account permanently.

#### **Method 2: Manual (GUI) Way**

1. Press `Win + X` → **Computer Management**
2. Go to **Local Users and Groups** → **Users**
3. Right-click on the user (e.g. `TestUser01`) → **Delete** → Yes

---

<img width="1004" height="745" alt="image" src="https://github.com/user-attachments/assets/a81693af-0f77-4c91-9242-209050ff3c7c" />

---
<img width="634" height="450" alt="image" src="https://github.com/user-attachments/assets/4006242d-2c89-4048-81f5-ab9f5b109714" />

---


### **Detection Command for Event 4726**

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4726
} -MaxEvents 10 | 
Select TimeCreated, 
       @{Name='CreatedBy';Expression={$_.Properties[1].Value}}, 
       @{Name='GroupName';Expression={$_.Properties[0].Value}} | 
Format-Table -AutoSize
```

---
```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          5/19/2026 9:18:38 PM
Event ID:      4726
Task Category: User Account Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-N4LQQSU0MFA.techcorp.local
Description:
A user account was deleted.

Subject:
	Security ID:		TECHCORP\administrator
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x11F18D

Target Account:
	Security ID:		TECHCORP\testuser01
	Account Name:		testuser01
	Account Domain:		TECHCORP

Additional Information:
	Privileges	-
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4726</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13824</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-05-20T04:18:38.0486350Z" />
    <EventRecordID>10181</EventRecordID>
    <Correlation />
    <Execution ProcessID="620" ThreadID="3544" />
    <Channel>Security</Channel>
    <Computer>WIN-N4LQQSU0MFA.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserName">testuser01</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetSid">S-1-5-21-3567083499-616298403-1270708564-1117</Data>
    <Data Name="SubjectUserSid">S-1-5-21-3567083499-616298403-1270708564-500</Data>
    <Data Name="SubjectUserName">administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x11f18d</Data>
    <Data Name="PrivilegeList">-</Data>
  </EventData>
</Event>
```
---
