

### **Event 4723 – Password Change Attempt**

**What it means:**  
This event is logged when a **user** tries to change their own password (not admin reset).

**SOC Importance:** Medium — Can be normal or indicate compromised account.

#### **Method 1: PowerShell** (Simulate user changing password)

```powershell
# Change password as the user himself (run as normal user if possible)
Set-ADAccountPassword -Identity "testuser01"
```

#### **Method 2: Manual GUI (Easiest)**

1. On the Windows machine, press `Ctrl + Alt + Del`
2. Click **Change a password**
3. Enter old password and new password

---

### In this picture a random user is trying to change the password of his account without permissions of administrator.

<img width="1024" height="763" alt="user changing a password" src="https://github.com/user-attachments/assets/710bf03a-52ae-4884-b2f6-a6aa6af38d6b" />


```powershell
# Detection Command for 4723
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4723
} -MaxEvents 5 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated     = $_.TimeCreated
        EventID         = 4723
        ChangedBy       = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
        TargetUser      = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```
---

<img width="626" height="441" alt="image" src="https://github.com/user-attachments/assets/4f565034-9dca-4ae0-8fc2-5bf24c24d37a" />
---


### **How to Generate Event 4723 (While Logged in as Admin)**

Here are **2 easy methods**:

---

### **Method 1: Best & Easiest (Recommended)**

1. **Log in as the test user** (not as Administrator)

   - On your Windows Server, press `Ctrl + Alt + Del`
   - Click **Switch User**
   - Log in with:
     - Username: `testuser01`
     - Password: `Password@123` (or whatever you set earlier)

2. Once logged in as **testuser01**, change the password:

   - Press `Ctrl + Alt + Del`
   - Click **Change a password**
   - Enter:
     - Old password → `Password@123`
     - New password → `MyNewPass@456`
     - Confirm password → same
   - Press Enter

3. Now log back in as Administrator and check Event Viewer.

This is the **cleanest** way to generate real Event 4723.

---

### **Method 2: Without Logging Out (Using PowerShell)**

While still logged in as Administrator, run this command:

```powershell
# Change password as the user himself
$User = "testuser01"
$OldPass = ConvertTo-SecureString "Password@123" -AsPlainText -Force
$NewPass = ConvertTo-SecureString "UserChanged@789" -AsPlainText -Force

Set-ADAccountPassword -Identity $User `
    -OldPassword $OldPass `
    -NewPassword $NewPass
```

This simulates the user changing their own password and should generate **Event 4723**.

---

### **After Doing the Above – Check the Event**

Run this detection command:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4723
} -MaxEvents 3 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        EventID     = 4723
        ChangedBy   = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
        TargetUser  = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```

---

### to solve permissions issues while logging in as random user

```powershell
# Allow normal users to log on locally
secedit /export /cfg c:\secpol.cfg
(Get-Content c:\secpol.cfg) -replace 'SeInteractiveLogonRight = .*', 'SeInteractiveLogonRight = *S-1-5-32-545' | Set-Content c:\secpol.cfg
secedit /configure /db secedit.sdb /cfg c:\secpol.cfg /areas USER_RIGHTS

# Restart the server (or gpupdate /force)
Restart-Computer
```
---

### Password relax policy

```powershell
# 1. Force Relax Password Policy (Most Important)
Set-ADDefaultDomainPasswordPolicy -Identity "techcorp.local" `
    -MinPasswordLength 6 `
    -ComplexityEnabled $false `
    -PasswordHistoryCount 0 `
    -MinPasswordAge 0.00:00:00
```
---
```powershell
# 1. Relax Password Policy (Lab Only)
Set-ADDefaultDomainPasswordPolicy -Identity "techcorp.local" `
    -MinPasswordLength 6 `
    -ComplexityEnabled $false `
    -PasswordHistoryCount 0 `
    -MaxPasswordAge "90.00:00:00"
```
---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          5/19/2026 7:15:19 PM
Event ID:      4723
Task Category: User Account Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-N4LQQSU0MFA.techcorp.local
Description:
An attempt was made to change an account's password.

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
	Privileges		-
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4723</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13824</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-05-20T02:15:19.5113159Z" />
    <EventRecordID>8926</EventRecordID>
    <Correlation />
    <Execution ProcessID="620" ThreadID="2936" />
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
