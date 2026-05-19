

### **Event 4720 – User Account Created**

**What it means:**  
This event is generated when a new user account is created in Active Directory.

**SOC Importance:** High — Attackers create backdoor accounts after compromising the system.

**Details captured in Event 4720:**
- Who created the account (`SubjectUserName`)
- New username (`TargetUserName`)
- Time of creation
- Computer where it was created

#### **Method 1: Using PowerShell (Recommended)**

```powershell
# Create a new user account
New-ADUser -Name "TestUser01" `
           -SamAccountName "testuser01" `
           -UserPrincipalName "testuser01@techcorp.local" `
           -Path "OU=IT,DC=techcorp,DC=local" `
           -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) `
           -Enabled $true
```

**Explanation of commands:**
- `New-ADUser` → Command to create new Active Directory user
- `-Name` → Full name shown in AD
- `-SamAccountName` → Login username
- `-UserPrincipalName` → Email format username
- `-Path` → Where to create the user (OU)
- `-AccountPassword` → Sets password
- `-Enabled $true` → Activates the account immediately

#### **Method 2: Manual (GUI) Way**

1. Open **Active Directory Users and Computers** (`dsa.msc`)
2. Go to **IT** OU → Right click → **New** → **User**
3. Fill:
   - Full name: `TestUser02`
   - User logon name: `testuser02`
4. Set password → Finish

<img width="818" height="530" alt="image" src="https://github.com/user-attachments/assets/a62a4c30-9084-4723-86d0-ec780f9cdf73" />


---

# Detection Command for 4720
```
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    -Id = 4720 
} -MaxEvents 5 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated     = $_.TimeCreated
        EventID         = 4720
        CreatedBy       = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
        NewUsername     = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
        ComputerName    = $_.MachineName
    }
} | Format-Table -AutoSize
```
<img width="736" height="443" alt="image" src="https://github.com/user-attachments/assets/a72dde19-d8a5-46d5-89c4-55faae92135c" />


or using mannual way apply filter or specific event to see only desired or identify from the list about the specific event in the event viewer.

**After running each command:**

1. Open **Event Viewer**
2. Go to **Windows Logs → Security**
3. Filter by the specific Event ID
4. Double-click the event and study all fields




<img width="628" height="444" alt="EVENT 4720" src="https://github.com/user-attachments/assets/f284a867-b085-46fc-97af-85eeb79aa6e4" />






``` Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          5/19/2026 6:12:58 PM
Event ID:      4720
Task Category: User Account Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-N4LQQSU0MFA.techcorp.local
Description:
A user account was created.

Subject:
	Security ID:		TECHCORP\Administrator
	Account Name:		Administrator
	Account Domain:		TECHCORP
	Logon ID:		0x40D32

New Account:
	Security ID:		TECHCORP\testuser01
	Account Name:		testuser01
	Account Domain:		TECHCORP

Attributes:
	SAM Account Name:	testuser01
	Display Name:		-
	User Principal Name:	testuser01@techcorp.local
	Home Directory:		-
	Home Drive:		-
	Script Path:		-
	Profile Path:		-
	User Workstations:	-
	Password Last Set:	<never>
	Account Expires:		<never>
	Primary Group ID:	513
	Allowed To Delegate To:	-
	Old UAC Value:		0x0
	New UAC Value:		0x11
	User Account Control:	
		Account Disabled
		'Normal Account' - Enabled
	User Parameters:	-
	SID History:		-
	Logon Hours:		<value not set>

Additional Information:
	Privileges		-
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4720</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13824</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-05-20T01:12:58.9582387Z" />
    <EventRecordID>7936</EventRecordID>
    <Correlation />
    <Execution ProcessID="620" ThreadID="1948" />
    <Channel>Security</Channel>
    <Computer>WIN-N4LQQSU0MFA.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserName">testuser01</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetSid">S-1-5-21-3567083499-616298403-1270708564-1117</Data>
    <Data Name="SubjectUserSid">S-1-5-21-3567083499-616298403-1270708564-500</Data>
    <Data Name="SubjectUserName">Administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x40d32</Data>
    <Data Name="PrivilegeList">-</Data>
    <Data Name="SamAccountName">testuser01</Data>
    <Data Name="DisplayName">-</Data>
    <Data Name="UserPrincipalName">testuser01@techcorp.local</Data>
    <Data Name="HomeDirectory">-</Data>
    <Data Name="HomePath">-</Data>
    <Data Name="ScriptPath">-</Data>
    <Data Name="ProfilePath">-</Data>
    <Data Name="UserWorkstations">-</Data>
    <Data Name="PasswordLastSet">%%1794</Data>
    <Data Name="AccountExpires">%%1794</Data>
    <Data Name="PrimaryGroupId">513</Data>
    <Data Name="AllowedToDelegateTo">-</Data>
    <Data Name="OldUacValue">0x0</Data>
    <Data Name="NewUacValue">0x11</Data>
    <Data Name="UserAccountControl">
		%%2080
		%%2084</Data>
    <Data Name="UserParameters">-</Data>

    <Data Name="SidHistory">-</Data>
    <Data Name="LogonHours">%%1793</Data>
  </EventData>
</Event>
```

---
