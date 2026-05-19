

### **Event 4724 – Password Reset by Admin**

**What it means:**  
This event is generated when someone (usually admin) resets another user’s password.

**SOC Importance:** High — Classic sign of account takeover preparation.

#### **Method 1: PowerShell**

```powershell
# Reset password of a user
Set-ADAccountPassword -Identity "testuser01" `
  -NewPassword (ConvertTo-SecureString "NewPass@456" -AsPlainText -Force) `
  -Reset
```

**Explanation:**
- `Set-ADAccountPassword` → Changes password
- `-Reset` → Means admin is forcing reset (doesn’t need old password)

#### **Method 2: Manual GUI**

1. Open `dsa.msc`
2. Right click on user → **Reset Password**
3. Enter new password → OK

---

<img width="391" height="268" alt="EVENT 4724" src="https://github.com/user-attachments/assets/b3900074-6eda-46a6-bfb6-6f9dc7e93766" />


```powershell
# Detection Command for 4724
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4724
} -MaxEvents 5 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated     = $_.TimeCreated
        EventID         = 4724
        ResetBy         = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
        TargetUser      = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```
---
<img width="733" height="473" alt="image" src="https://github.com/user-attachments/assets/8227595a-6117-4783-947f-e213d0a5a68c" />

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          5/19/2026 6:31:46 PM
Event ID:      4724
Task Category: User Account Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-N4LQQSU0MFA.techcorp.local
Description:
An attempt was made to reset an account's password.

Subject:
	Security ID:		TECHCORP\Administrator
	Account Name:		Administrator
	Account Domain:		TECHCORP
	Logon ID:		0x40D32

Target Account:
	Security ID:		TECHCORP\testuser01
	Account Name:		testuser01
	Account Domain:		TECHCORP
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4724</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13824</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-05-20T01:31:46.7959264Z" />
    <EventRecordID>8127</EventRecordID>
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
  </EventData>
</Event>
```

